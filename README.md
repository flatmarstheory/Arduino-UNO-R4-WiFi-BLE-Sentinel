# Arduino UNO R4 WiFi BLE Sentinel

[![Project Status](https://img.shields.io/badge/Status-Active-success)](https://github.com/YOUR_USERNAME/uno-ble-sentinel)
[![Hardware](https://img.shields.io/badge/Hardware-Arduino_UNO_R4_WiFi-00979D)](https://store.arduino.cc/products/uno-r4-wifi)
[![Language](https://img.shields.io/badge/Language-C++_/_Arduino-00979D)](https://www.arduino.cc/)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey.svg)](https://unlicense.org/)

A specialized cybersecurity awareness tool that transforms an Arduino UNO R4 WiFi into a Bluetooth Low Energy (BLE) monitor. It identifies nearby "input-injection" risks—such as rogue keyboards, mice, or remotes—and provides real-time proximity alerts via a physical LED and a mobile-friendly web dashboard.

## 📺 Project Demo
Click the image below to watch the full project walkthrough and live demonstration:

[![Arduino BLE Sentinel Demo](https://img.youtube.com/vi/0ydIEh2BYK0/0.jpg)](https://www.youtube.com/watch?v=0ydIEh2BYK0)

### 📑 Video Chapters
* **0:00** - What this device does and why it matters
* **0:45** - Hardware overview and placement
* **1:05** - How the BLE detection logic works
* **1:55** - Live mobile dashboard demonstration
* **2:40** - Vendor lookup and alert behavior
* **3:05** - Key takeaways and responsible use

---

## 🚀 Key Features
* **BLE Scrutiny:** Continuously scans for BLE HID candidates (0x1812 service) and patterns in device names (Keyboard, Mouse, Remote).
* **Proximity Alerts:** Flags devices as "Suspicious" if they are HID-capable and have a strong signal (RSSI > -65dBm).
* **Mobile-First Dashboard:** Hosts an asynchronous web UI at `http://192.168.100.223/` with auto-refreshing device cards.
* **Vendor Enrichment:** Integrates with the MACLookup API to resolve hardware manufacturer names directly on the microcontroller.
* **RAM-Safe Implementation:** Built to run efficiently on the UNO R4 by using streaming proxies for large JSON data.

## 🛠️ System Architecture

### 1. Detection Engine
The scanner looks for specific BLE advertisement flags:
- **HID Flags:** Advertised service UUID `0x1812`.
- **Name Hints:** Strings like "KEYBOARD" or "MOUSE".
- **LAA Detection:** Checks if the MAC address is Locally Administered (randomized).

### 2. Proximity Rules
When an input-capable device is detected within a certain RSSI threshold, the onboard **Sentinel LED** flashes, providing an immediate physical warning.

---

## 📥 Installation & Setup

### 1. Hardware Requirements
* **Arduino UNO R4 WiFi**.
* Power source (USB or battery).

### 2. Software & Libraries
Install the following via the Arduino Library Manager:
* `WiFiS3`
* `ArduinoBLE`

### 3. Configuration
1. Open `src/sentinel.ino`.
2. Update the Wi-Fi credentials:
   ```cpp
   static const char* WIFI_SSID = "Your_SSID";
   static const char* WIFI_PASS = "Your_Password";
    ```

3. Flash the code to your Arduino.
4. Access the dashboard at the IP address printed to the Serial Monitor (Default: `192.168.100.223`).

## 🔐 Cybersecurity Disclaimer

This is a **detection and awareness tool**—not a jammer and not a blocker. It is designed for educational and defensive use in authorized environments only. Always follow local laws regarding wireless monitoring.

## 📜 License

This project is dedicated to the public domain under **The Unlicense**. See the `LICENSE` file for details.

---

*Developed by Rai Bahadur Singh.*
