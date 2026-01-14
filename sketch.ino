/*
  UNO R4 WiFi BLE Sentinel (RAM-safe) + Mobile Web UI + External enrichment (MACLookup)

  What it does:
    - BLE scans advertisements (detection/alerting only; NOT jamming)
    - Flags BLE HID candidates (advertised HID service 0x1812) + proximity (RSSI)
    - Web dashboard (mobile-first cards) at http://192.168.100.223/
    - Vendor enrichment: background fetch of company name from:
        https://api.maclookup.app/v2/macs/{mac}/company/name
    - Full enrichment on-demand: tap "Details" -> Arduino proxies:
        https://api.maclookup.app/v2/macs/{mac}
      (streamed; no big RAM buffers)

  Libraries:
    - WiFiS3
    - ArduinoBLE

  If you STILL get RAM errors:
    - reduce MAX_DEVICES to 12 or 8
    - reduce MAX_ALERTS to 8
*/

#include <WiFiS3.h>
#include <ArduinoBLE.h>

static const char* WIFI_SSID = "Sweet Home";
static const char* WIFI_PASS = "*************";

IPAddress LOCAL_IP(192, 168, 100, 223);
IPAddress GATEWAY(192, 168, 100, 1);
IPAddress SUBNET(255, 255, 255, 0);
IPAddress DNS(192, 168, 100, 1);

WiFiServer server(80);
WiFiSSLClient ext;

#define ALERT_LED LED_BUILTIN

// Tune
static const int8_t  HID_RSSI_SUSPICIOUS = -65;
static const uint32_t DEVICE_STALE_MS = 30000;
static const uint32_t ALERT_LED_MS   = 600;

// External API throttling (be nice to rate limits)
static const uint32_t EXT_MIN_GAP_MS = 2500;
static uint32_t g_lastExtMs = 0;
static int g_extLastStatus = 0;
static char g_extLastErr[32] = {0};

static bool g_bleOk = false;

static const char* EXT_HOST = "api.maclookup.app";
static const int   EXT_PORT = 443;

// --- Small RAM footprint data ---
static const uint8_t MAX_DEVICES = 16;   // reduce if needed
static const uint8_t MAX_ALERTS  = 12;

enum DevFlags : uint8_t {
  DF_HID          = 1 << 0,
  DF_SUS          = 1 << 1,
  DF_LAA          = 1 << 2,
  DF_VENDOR_KNOWN = 1 << 3,
  DF_VENDOR_PEND  = 1 << 4
};

struct DeviceEntry {
  uint8_t inUse;
  char    addr[18];     // "AA:BB:CC:DD:EE:FF"
  char    name[24];
  char    vendor[28];   // cached company name (small)
  int8_t  rssi;
  int8_t  avg;
  uint16_t seen;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint8_t  flags;
};

struct AlertEntry {
  uint32_t ts;
  char addr[18];
  int8_t rssi;
  char reason[52];
};

static DeviceEntry devices[MAX_DEVICES];
static AlertEntry  alerts[MAX_ALERTS];
static uint8_t alertHead = 0;
static uint8_t alertCount = 0;
static uint32_t alertLedUntil = 0;

// Vendor lookup queue (tiny)
struct QItem { uint8_t idx; };
static const uint8_t QN = 16;
static QItem q[QN];
static uint8_t qh = 0, qt = 0, qc = 0;

static void safeCopy(char* dst, size_t dstSize, const char* src) {
  if (!dst || dstSize == 0) return;
  if (!src) { dst[0] = '\0'; return; }
  size_t i = 0;
  for (; i + 1 < dstSize && src[i] != '\0'; i++) dst[i] = src[i];
  dst[i] = '\0';
}

static void trim(char* s) {
  if (!s) return;
  int n = (int)strlen(s);
  while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n' || s[n-1] == ' ' || s[n-1] == '\t')) {
    s[n-1] = '\0';
    n--;
  }
  int i = 0;
  while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') i++;
  if (i > 0) {
    int j = 0;
    while (s[i]) s[j++] = s[i++];
    s[j] = '\0';
  }
}

static bool containsNoCase(const char* hay, const char* needle) {
  if (!hay || !needle || !needle[0]) return false;
  for (size_t i = 0; hay[i]; i++) {
    size_t j = 0;
    while (needle[j] && hay[i + j]) {
      char a = hay[i + j];
      char b = needle[j];
      if (a >= 'a' && a <= 'z') a = char(a - 'a' + 'A');
      if (b >= 'a' && b <= 'z') b = char(b - 'a' + 'A');
      if (a != b) break;
      j++;
    }
    if (!needle[j]) return true;
  }
  return false;
}

static int hexByte(const char* p) {
  auto h = [](char c)->int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  int a = h(p[0]), b = h(p[1]);
  if (a < 0 || b < 0) return -1;
  return (a << 4) | b;
}

static bool isLocallyAdministered(const char* mac) {
  int b = hexByte(mac);
  if (b < 0) return false;
  return (b & 0x02) != 0;
}

static void addAlert(const char* addr, int8_t rssi, const char* reason) {
  AlertEntry& e = alerts[alertHead];
  e.ts = millis();
  safeCopy(e.addr, sizeof(e.addr), addr);
  e.rssi = rssi;
  safeCopy(e.reason, sizeof(e.reason), reason);

  alertHead = (alertHead + 1) % MAX_ALERTS;
  if (alertCount < MAX_ALERTS) alertCount++;

  alertLedUntil = millis() + ALERT_LED_MS;
}

static int findDeviceByAddr(const char* addr) {
  for (uint8_t i = 0; i < MAX_DEVICES; i++) {
    if (devices[i].inUse && strncmp(devices[i].addr, addr, sizeof(devices[i].addr)) == 0) return (int)i;
  }
  return -1;
}

static uint8_t allocDeviceSlot() {
  for (uint8_t i = 0; i < MAX_DEVICES; i++) if (!devices[i].inUse) return i;
  uint32_t oldestAge = 0;
  uint8_t oldestIdx = 0;
  for (uint8_t i = 0; i < MAX_DEVICES; i++) {
    uint32_t age = millis() - devices[i].lastSeen;
    if (age >= oldestAge) { oldestAge = age; oldestIdx = i; }
  }
  return oldestIdx;
}

static void qPush(uint8_t idx) {
  if (qc >= QN) return;
  q[qt].idx = idx;
  qt = (qt + 1) % QN;
  qc++;
}
static bool qPop(uint8_t &idx) {
  if (qc == 0) return false;
  idx = q[qh].idx;
  qh = (qh + 1) % QN;
  qc--;
  return true;
}

// --- minimal line reader ---
static int readLine(WiFiClient& c, char* out, int outSize, uint32_t timeoutMs) {
  if (outSize <= 0) return 0;
  int n = 0;
  uint32_t start = millis();
  while (millis() - start < timeoutMs) {
    while (c.available()) {
      char ch = (char)c.read();
      if (ch == '\r') continue;
      if (ch == '\n') { out[n] = '\0'; return n; }
      if (n < outSize - 1) out[n++] = ch;
    }
    delay(1);
  }
  out[n] = '\0';
  return n;
}

static void httpHeader(WiFiClient& c, const char* status, const char* ct) {
  c.print(F("HTTP/1.1 "));
  c.print(status);
  c.print(F("\r\nContent-Type: "));
  c.print(ct);
  c.print(F("\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"));
}

static void jsonEsc(WiFiClient& c, const char* s) {
  c.print('"');
  if (s) {
    for (size_t i = 0; s[i]; i++) {
      char ch = s[i];
      if (ch == '\\') c.print(F("\\\\"));
      else if (ch == '"') c.print(F("\\\""));
      else if (ch == '\n') c.print(F("\\n"));
      else if (ch == '\r') c.print(F("\\r"));
      else if (ch == '\t') c.print(F("\\t"));
      else {
        if ((uint8_t)ch < 0x20) c.print(' ');
        else c.print(ch);
      }
    }
  }
  c.print('"');
}

// --- BLE HID detection (cheap) ---
static bool advHasHIDService(BLEDevice& d) {
  for (int i = 0; i < 8; i++) {
    String u = d.advertisedServiceUuid(i);
    if (u.length() == 0) break;
    u.toUpperCase();
    if (u == "1812") return true;
    if (u.indexOf("00001812-0000-1000-8000-00805F9B34FB") >= 0) return true;
    if (u.endsWith("1812")) return true;
  }
  return false;
}

static bool nameHintsHID(const char* name) {
  if (!name || !name[0]) return false;
  if (containsNoCase(name, "KEYBOARD")) return true;
  if (containsNoCase(name, "MOUSE")) return true;
  if (containsNoCase(name, "HID")) return true;
  if (containsNoCase(name, "REMOTE")) return true;
  if (containsNoCase(name, "CLICK")) return true;
  return false;
}

static void processPeripheral(BLEDevice& p) {
  char addr[18]; safeCopy(addr, sizeof(addr), p.address().c_str());
  char name[24]; safeCopy(name, sizeof(name), p.localName().c_str());
  int8_t rssi = (int8_t)p.rssi();
  uint32_t now = millis();

  int idx = findDeviceByAddr(addr);
  bool isNew = false;

  if (idx < 0) {
    uint8_t slot = allocDeviceSlot();
    devices[slot] = DeviceEntry{};
    devices[slot].inUse = 1;
    safeCopy(devices[slot].addr, sizeof(devices[slot].addr), addr);
    safeCopy(devices[slot].name, sizeof(devices[slot].name), name);
    devices[slot].vendor[0] = '\0';
    devices[slot].firstSeen = now;
    devices[slot].lastSeen = now;
    devices[slot].seen = 0;
    devices[slot].avg = rssi;
    devices[slot].rssi = rssi;
    devices[slot].flags = 0;
    if (isLocallyAdministered(addr)) devices[slot].flags |= DF_LAA;
    idx = (int)slot;
    isNew = true;
  } else {
    if (devices[idx].name[0] == '\0' && name[0] != '\0') safeCopy(devices[idx].name, sizeof(devices[idx].name), name);
  }

  DeviceEntry& d = devices[idx];
  d.rssi = rssi;
  d.avg = (int8_t)((d.avg * 7 + rssi * 3) / 10);
  d.lastSeen = now;
  if (d.seen < 65535) d.seen++;

  bool hid = advHasHIDService(p) || nameHintsHID(d.name);
  if (hid) d.flags |= DF_HID; else d.flags &= ~DF_HID;

  bool sus = false;
  if (hid && rssi >= HID_RSSI_SUSPICIOUS) sus = true;
  if (hid && containsNoCase(d.name, "KEY")) sus = true;
  if (sus) d.flags |= DF_SUS; else d.flags &= ~DF_SUS;

  static uint8_t lastSus[MAX_DEVICES] = {0};
  if (isNew && hid) addAlert(d.addr, rssi, "New HID-like BLE device (0x1812/name)");
  if (!lastSus[idx] && sus) addAlert(d.addr, rssi, "HID-like device suspicious (strong RSSI)");
  lastSus[idx] = sus ? 1 : 0;

  if (!(d.flags & DF_VENDOR_KNOWN) && !(d.flags & DF_VENDOR_PEND)) {
    d.flags |= DF_VENDOR_PEND;
    qPush((uint8_t)idx);
  }
}

// --- External API: fetch vendor name (small response) ---
static bool extConnect() {
  g_extLastErr[0] = '\0';
  if (WiFi.status() != WL_CONNECTED) { safeCopy(g_extLastErr, sizeof(g_extLastErr), "wifi_down"); return false; }
  if (!ext.connect(EXT_HOST, EXT_PORT)) { safeCopy(g_extLastErr, sizeof(g_extLastErr), "ssl_fail"); return false; }
  return true;
}

static int extGetStatusLine(char* line, int maxLen) {
  int n = readLine(ext, line, maxLen, 3500);
  if (n <= 0) return 0;
  const char* sp = strchr(line, ' ');
  if (!sp) return 0;
  return atoi(sp + 1);
}

static void extSkipHeaders() {
  char line[140];
  while (true) {
    int n = readLine(ext, line, sizeof(line), 3500);
    if (n <= 0) break;
    if (line[0] == '\0') break;
  }
}

static void extFetchVendor(uint8_t idx) {
  DeviceEntry& d = devices[idx];
  if (!d.inUse) return;

  if (millis() - g_lastExtMs < EXT_MIN_GAP_MS) return;
  g_lastExtMs = millis();

  if (!extConnect()) {
    d.flags &= ~DF_VENDOR_PEND;
    safeCopy(d.vendor, sizeof(d.vendor), "UNKNOWN");
    d.flags |= DF_VENDOR_KNOWN;
    return;
  }

  char path[96];
  snprintf(path, sizeof(path), "/v2/macs/%s/company/name", d.addr);

  ext.print(F("GET "));
  ext.print(path);
  ext.print(F(" HTTP/1.1\r\nHost: "));
  ext.print(EXT_HOST);
  ext.print(F("\r\nUser-Agent: UNO-R4-BLE-Sentinel\r\nConnection: close\r\n\r\n"));

  char statusLine[160];
  int code = extGetStatusLine(statusLine, sizeof(statusLine));
  g_extLastStatus = code;

  extSkipHeaders();

  char body[64];
  int pos = 0;
  uint32_t start = millis();
  while (millis() - start < 5000) {
    while (ext.available()) {
      char ch = (char)ext.read();
      if (pos < (int)sizeof(body) - 1) body[pos++] = ch;
    }
    if (!ext.connected() && !ext.available()) break;
    delay(1);
  }
  body[pos] = '\0';
  ext.stop();

  trim(body);
  if (code == 200 && body[0] != '\0') {
    if (strcmp(body, "*NO COMPANY*") == 0) safeCopy(d.vendor, sizeof(d.vendor), "UNKNOWN");
    else safeCopy(d.vendor, sizeof(d.vendor), body);
  } else {
    safeCopy(d.vendor, sizeof(d.vendor), "UNKNOWN");
  }

  d.flags &= ~DF_VENDOR_PEND;
  d.flags |= DF_VENDOR_KNOWN;
}

// --- Proxy full JSON details on-demand: /lookup?mac=AA:BB:... ---
static void serveLookupProxy(WiFiClient& client, const char* mac) {
  if (millis() - g_lastExtMs < 250) { // tiny anti-spam
    httpHeader(client, "429 Too Many Requests", "application/json; charset=utf-8");
    client.print(F("{\"error\":\"rate_limited\"}"));
    return;
  }
  g_lastExtMs = millis();

  if (!extConnect()) {
    httpHeader(client, "502 Bad Gateway", "application/json; charset=utf-8");
    client.print(F("{\"error\":\"ext_connect_failed\"}"));
    return;
  }

  char path[72];
  snprintf(path, sizeof(path), "/v2/macs/%s", mac);

  ext.print(F("GET "));
  ext.print(path);
  ext.print(F(" HTTP/1.1\r\nHost: "));
  ext.print(EXT_HOST);
  ext.print(F("\r\nUser-Agent: UNO-R4-BLE-Sentinel\r\nConnection: close\r\n\r\n"));

  char statusLine[160];
  int code = extGetStatusLine(statusLine, sizeof(statusLine));
  g_extLastStatus = code;

  extSkipHeaders();

  if (code == 200) httpHeader(client, "200 OK", "application/json; charset=utf-8");
  else if (code == 404) httpHeader(client, "404 Not Found", "application/json; charset=utf-8");
  else httpHeader(client, "502 Bad Gateway", "application/json; charset=utf-8");

  uint32_t start = millis();
  while (millis() - start < 7000) {
    while (ext.available()) {
      uint8_t b = (uint8_t)ext.read();
      client.write(b);
    }
    if (!ext.connected() && !ext.available()) break;
    delay(1);
  }
  ext.stop();
}

// --- Web: mobile-first HTML + JS ---
static void serveRoot(WiFiClient& client) {
  httpHeader(client, "200 OK", "text/html; charset=utf-8");
  client.print(F(
    "<!doctype html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'/>"
    "<title>UNO R4 BLE Sentinel</title>"
    "<style>"
    ":root{--bg:#0b0f1a;--card:#0f1626;--mut:#9aa4b2;--line:#1f2a3d;--g:#2ecc71;--r:#ff4d4d;--y:#ffaa00;}"
    "html,body{margin:0;background:var(--bg);color:#e8eef8;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;}"
    ".top{position:sticky;top:0;z-index:9;background:rgba(11,15,26,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}"
    ".wrap{max-width:980px;margin:0 auto;padding:12px}"
    ".row{display:flex;justify-content:space-between;gap:10px;align-items:center}"
    "h1{font-size:16px;margin:0;font-weight:800;letter-spacing:.2px}"
    ".pill{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:999px;padding:4px 10px;font-size:12px}"
    ".dot{width:8px;height:8px;border-radius:99px;background:var(--y)}"
    ".dot.g{background:var(--g)} .dot.r{background:var(--r)}"
    ".meta{margin-top:8px;color:var(--mut);font-size:12px;line-height:1.35}"
    ".cards{display:grid;gap:10px;padding:12px}"
    ".card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px}"
    ".mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
    ".mut{color:var(--mut)}"
    ".big{font-weight:850;font-size:15px}"
    ".chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}"
    ".chip{border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:3px 8px;font-size:12px}"
    ".chip.r{border-color:rgba(255,77,77,.55);color:#ffd3d3}"
    ".chip.g{border-color:rgba(46,204,113,.55);color:#c9ffe1}"
    ".chip.y{border-color:rgba(255,170,0,.6);color:#ffe3b3}"
    ".btn{border:1px solid rgba(255,255,255,.14);background:transparent;color:#e8eef8;border-radius:12px;padding:7px 10px;font-weight:750;font-size:12px}"
    ".btn:active{transform:scale(.98)}"
    ".split{display:grid;grid-template-columns:1fr;gap:10px}"
    "@media (min-width:920px){.split{grid-template-columns:2fr 1fr}}"
    ".modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:flex-end;justify-content:center;padding:12px;z-index:20}"
    ".sheet{width:min(980px,100%);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px;max-height:70vh;overflow:auto}"
    "pre{white-space:pre-wrap;word-break:break-word;font-size:12px;color:#dbe7ff}"
    "</style></head><body>"
    "<div class='top'><div class='wrap'>"
      "<div class='row'>"
        "<h1>UNO R4 WiFi BLE Sentinel</h1>"
        "<span class='pill'><span id='dot' class='dot'></span><span id='status'>loading…</span></span>"
      "</div>"
      "<div class='meta'>Detection/alerting only. Flags BLE HID candidates (0x1812/name) + proximity (RSSI). Vendor via MACLookup; tap Details for full JSON proxy.</div>"
      "<div class='meta mono' id='w'></div>"
    "</div></div>"
    "<div class='wrap split'>"
      "<div class='cards' id='dev'></div>"
      "<div class='cards' id='al'></div>"
    "</div>"
    "<div class='modal' id='m' onclick='hide()'><div class='sheet' onclick='event.stopPropagation()'>"
      "<div class='row'><div class='big'>MACLookup details</div><button class='btn' onclick='hide()'>Close</button></div>"
      "<div class='mut mono' id='maddr' style='margin-top:6px'></div>"
      "<pre id='mjson' style='margin-top:10px'></pre>"
    "</div></div>"
    "<script src='/app.js'></script>"
    "</body></html>"
  ));
}

static void serveJs(WiFiClient& client) {
  httpHeader(client, "200 OK", "application/javascript; charset=utf-8");
  client.print(F(
    "const $=s=>document.querySelector(s);\n"
    "function esc(s){return (s||'').replace(/[&<>\"']/g,c=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",\"\\\"\":\"&quot;\",\"'\":\"&#39;\"}[c]))}\n"
    "function fmt(ms){if(ms<1000)return ms+'ms'; if(ms<60000)return (ms/1000).toFixed(1)+'s'; return (ms/60000).toFixed(1)+'m';}\n"
    "function chip(t,c){return `<span class='chip ${c||''}'>${esc(t)}</span>`}\n"
    "function show(addr,json){$('#m').style.display='flex'; $('#maddr').textContent=addr; $('#mjson').textContent=json;}\n"
    "function hide(){ $('#m').style.display='none'; }\n"
    "window.hide=hide;\n"
    "async function details(addr){\n"
    "  try{\n"
    "    const r=await fetch('/lookup?mac='+encodeURIComponent(addr),{cache:'no-store'});\n"
    "    const t=await r.text();\n"
    "    show(addr, t);\n"
    "  }catch(e){ show(addr, '{\"error\":\"fetch_failed\"}'); }\n"
    "}\n"
    "window.details=details;\n"
    "async function tick(){\n"
    "  try{\n"
    "    const r=await fetch('/api',{cache:'no-store'});\n"
    "    const j=await r.json();\n"
    "    const ok = j.stats?.wifi_ok && j.stats?.ble_ok;\n"
    "    $('#dot').className='dot '+(ok?'g':'r');\n"
    "    $('#status').textContent = ok ? `LIVE · ${j.wifi.ip}` : 'CHECK';\n"
    "    $('#w').textContent = `WiFi: ${j.wifi.ssid} · RSSI ${j.wifi.rssi} · ext ${j.ext.last_status} ${j.ext.last_err||''}`;\n"
    "    let dhtml='';\n"
    "    const dev=j.devices||[];\n"
    "    if(!dev.length){ dhtml = `<div class='card'><div class='mut'>No BLE devices yet. Wait a few seconds or move closer.</div></div>`; }\n"
    "    else dev.forEach(d=>{\n"
    "      const chips=[];\n"
    "      if(d.hid) chips.push(chip('HID','g'));\n"
    "      if(d.sus) chips.push(chip('SUSP','r'));\n"
    "      if(d.laa) chips.push(chip('LAA','y'));\n"
    "      const vend = d.vendor && d.vendor.length ? d.vendor : (d.vpend ? 'resolving…' : '');\n"
    "      dhtml += `<div class='card'>\n"
    "        <div class='row'>\n"
    "          <div>\n"
    "            <div class='big mono'>${esc(d.addr)}</div>\n"
    "            <div class='mut' style='margin-top:3px'>${esc(d.name||'')} ${vend?('· '+esc(vend)) : ''}</div>\n"
    "          </div>\n"
    "          <div style='text-align:right'>\n"
    "            <div class='big mono'>${d.rssi} dBm</div>\n"
    "            <div class='mut mono' style='margin-top:2px'>avg ${d.avg} · ${fmt(d.age_ms)}</div>\n"
    "          </div>\n"
    "        </div>\n"
    "        <div class='chips'>${chips.join('')}</div>\n"
    "        <div class='row' style='margin-top:10px'>\n"
    "          <div class='mut mono'>seen ${d.seen}</div>\n"
    "          <button class='btn' onclick='details(\"${d.addr}\")'>Details</button>\n"
    "        </div>\n"
    "      </div>`;\n"
    "    });\n"
    "    $('#dev').innerHTML=dhtml;\n"
    "    let ahtml='';\n"
    "    const al=j.alerts||[];\n"
    "    if(!al.length) ahtml = `<div class='card'><div class='mut'>No alerts yet.</div></div>`;\n"
    "    else al.forEach(a=>{\n"
    "      ahtml += `<div class='card'>\n"
    "        <div class='big'>${esc(a.reason)}</div>\n"
    "        <div class='mut mono' style='margin-top:6px'>${esc(a.addr)} · RSSI ${a.rssi} · ${fmt(a.age_ms)} ago</div>\n"
    "      </div>`;\n"
    "    });\n"
    "    $('#al').innerHTML=ahtml;\n"
    "  }catch(e){ $('#status').textContent='OFFLINE'; $('#dot').className='dot r'; }\n"
    "}\n"
    "setInterval(tick, 900);\n"
    "tick();\n"
  ));
}

static void serveApi(WiFiClient& client) {
  httpHeader(client, "200 OK", "application/json; charset=utf-8");
  uint32_t now = millis();
  bool wifiOk = (WiFi.status() == WL_CONNECTED);

  client.print(F("{\"wifi\":{"));
  client.print(F("\"ok\":")); client.print(wifiOk ? F("true") : F("false"));
  client.print(F(",\"ip\":")); jsonEsc(client, WiFi.localIP().toString().c_str());
  client.print(F(",\"ssid\":")); jsonEsc(client, WIFI_SSID);
  client.print(F(",\"rssi\":")); client.print(WiFi.RSSI());
  client.print(F("},\"ext\":{"));
  client.print(F("\"last_status\":")); client.print(g_extLastStatus);
  client.print(F(",\"last_err\":")); jsonEsc(client, g_extLastErr);
  client.print(F("},\"stats\":{"));
  client.print(F("\"wifi_ok\":")); client.print(wifiOk ? F("true") : F("false"));
  client.print(F(",\"ble_ok\":")); client.print(g_bleOk ? F("true") : F("false"));
  client.print(F(",\"q\":")); client.print(qc);
  client.print(F("},\"devices\":["));

  bool first = true;
  for (uint8_t i = 0; i < MAX_DEVICES; i++) {
    if (!devices[i].inUse) continue;
    uint32_t age = now - devices[i].lastSeen;
    if (age > DEVICE_STALE_MS) continue;

    if (!first) client.print(',');
    first = false;

    client.print('{');
    client.print(F("\"addr\":")); jsonEsc(client, devices[i].addr);
    client.print(F(",\"name\":")); jsonEsc(client, devices[i].name);
    client.print(F(",\"vendor\":")); jsonEsc(client, (devices[i].flags & DF_VENDOR_KNOWN) ? devices[i].vendor : "");
    client.print(F(",\"vpend\":")); client.print((devices[i].flags & DF_VENDOR_PEND) ? F("true") : F("false"));
    client.print(F(",\"rssi\":")); client.print((int)devices[i].rssi);
    client.print(F(",\"avg\":"));  client.print((int)devices[i].avg);
    client.print(F(",\"seen\":")); client.print(devices[i].seen);
    client.print(F(",\"age_ms\":")); client.print(age);
    client.print(F(",\"hid\":")); client.print((devices[i].flags & DF_HID) ? F("true") : F("false"));
    client.print(F(",\"sus\":")); client.print((devices[i].flags & DF_SUS) ? F("true") : F("false"));
    client.print(F(",\"laa\":")); client.print((devices[i].flags & DF_LAA) ? F("true") : F("false"));
    client.print('}');
  }

  client.print(F("],\"alerts\":["));
  bool af = true;
  for (uint8_t k = 0; k < alertCount; k++) {
    int idx = (int)alertHead - 1 - (int)k;
    while (idx < 0) idx += MAX_ALERTS;
    AlertEntry &a = alerts[idx];
    uint32_t age = now - a.ts;

    if (!af) client.print(',');
    af = false;

    client.print('{');
    client.print(F("\"addr\":")); jsonEsc(client, a.addr);
    client.print(F(",\"rssi\":")); client.print((int)a.rssi);
    client.print(F(",\"reason\":")); jsonEsc(client, a.reason);
    client.print(F(",\"age_ms\":")); client.print(age);
    client.print('}');
  }
  client.print(F("]}"));
}

static bool parseQueryMac(const char* path, char* out, int outMax) {
  // expects /lookup?mac=AA%3ABB...
  const char* q = strchr(path, '?');
  if (!q) return false;
  const char* p = strstr(q, "mac=");
  if (!p) return false;
  p += 4;
  int n = 0;
  while (*p && *p != '&' && n < outMax - 1) {
    char ch = *p++;
    if (ch == '%') {
      if (p[0] && p[1]) {
        char h1 = p[0], h2 = p[1];
        auto hex = [](char c)->int {
          if (c >= '0' && c <= '9') return c - '0';
          if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
          if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
          return -1;
        };
        int a = hex(h1), b = hex(h2);
        if (a >= 0 && b >= 0) {
          out[n++] = (char)((a << 4) | b);
          p += 2;
          continue;
        }
      }
    }
    if (ch == '+') ch = ' ';
    out[n++] = ch;
  }
  out[n] = '\0';
  return n >= 11; // minimal sanity
}

static void handleHttp() {
  WiFiClient client = server.available();
  if (!client) return;

  char reqLine[180];
  int rl = readLine(client, reqLine, sizeof(reqLine), 450);
  if (rl <= 0) { client.stop(); return; }

  // eat headers
  while (true) {
    char h[160];
    int l = readLine(client, h, sizeof(h), 450);
    if (l <= 0) break;
    if (h[0] == '\0') break;
  }

  // parse path from "GET /path HTTP/1.1"
  char path[120] = {0};
  int i = 0;
  while (reqLine[i] && reqLine[i] != ' ') i++;
  while (reqLine[i] == ' ') i++;
  int p = 0;
  while (reqLine[i] && reqLine[i] != ' ' && p < (int)sizeof(path) - 1) path[p++] = reqLine[i++];
  path[p] = '\0';

  if (strncmp(path, "/app.js", 7) == 0) {
    serveJs(client);
  } else if (strncmp(path, "/api", 4) == 0) {
    serveApi(client);
  } else if (strncmp(path, "/lookup", 7) == 0) {
    char mac[24];
    if (!parseQueryMac(path, mac, sizeof(mac))) {
      httpHeader(client, "400 Bad Request", "application/json; charset=utf-8");
      client.print(F("{\"error\":\"missing_mac\"}"));
    } else {
      serveLookupProxy(client, mac);
    }
  } else {
    serveRoot(client);
  }

  delay(1);
  client.stop();
}

static void runVendorQueue() {
  if (qc == 0) return;
  if (millis() - g_lastExtMs < EXT_MIN_GAP_MS) return;

  uint8_t idx;
  if (!qPop(idx)) return;
  if (idx >= MAX_DEVICES) return;
  if (!devices[idx].inUse) return;

  extFetchVendor(idx);
}

void setup() {
  pinMode(ALERT_LED, OUTPUT);
  digitalWrite(ALERT_LED, LOW);

  Serial.begin(115200);
  while (!Serial) {}

  WiFi.config(LOCAL_IP, DNS, GATEWAY, SUBNET);

  Serial.println("Connecting WiFi...");
  int st = WL_IDLE_STATUS;
  while (st != WL_CONNECTED) {
    st = WiFi.begin(WIFI_SSID, WIFI_PASS);
    delay(800);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());

  server.begin();
  Serial.println("HTTP server started.");

  Serial.println("Starting BLE...");
  g_bleOk = BLE.begin();
  if (!g_bleOk) {
    Serial.println("BLE.begin() failed (check firmware / ArduinoBLE).");
  } else {
    Serial.println("BLE scanning...");
    BLE.scan(true); // with duplicates => RSSI updates
  }
}

void loop() {
  if (g_bleOk) {
    BLEDevice p = BLE.available();
    while (p) {
      processPeripheral(p);
      p = BLE.available();
    }
  }

  uint32_t now = millis();
  if (now < alertLedUntil) digitalWrite(ALERT_LED, (now / 80) % 2 ? HIGH : LOW);
  else digitalWrite(ALERT_LED, LOW);

  runVendorQueue();
  handleHttp();

  // cleanup stale
  for (uint8_t i = 0; i < MAX_DEVICES; i++) {
    if (devices[i].inUse && (millis() - devices[i].lastSeen) > (DEVICE_STALE_MS * 6UL)) {
      devices[i].inUse = 0;
    }
  }
}
