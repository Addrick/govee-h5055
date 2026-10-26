# Govee H5055 Local BLE & GATT Web Controller

A standalone, zero-cloud local controller and web dashboard for the **Govee H5055** 6-probe Bluetooth BBQ thermometer. Runs on Windows, Linux, or macOS using [`bleak`](https://github.com/hbldh/bleak) and Python's standard library (`asyncio`), serving a responsive web UI for both desktop and mobile browsers over local Wi-Fi.

## Features

- **1-Second Active GATT Polling (`0xAA 0x07`):** Queries all 6 probe temperatures and the 6-bit probe-presence mask in a single 20-byte GATT transaction at configurable intervals (`1s`–`60s`), bypassing the slow (~1.54s × 3 pair rotation) passive advertisement cycle.
- **Passive BLE Broadcast Fallback:** Automatically discovers the H5055 and decodes its passive BLE manufacturer advertisements when unconnected.
- **Direct Hardware Configuration (`0x33` / `0xAA` registers):**
  - Read and write per-probe **High / Low hardware alarm limits** (`0x33 0x01` / `0xAA 0x01`) for Probes 1–6 (controls the physical thermometer's LCD alert limits and 90 dB buzzer).
  - Switch the thermometer's **physical LCD unit** between `°F` and `°C` (`0x33 0x03` / `0xAA 0x03`).
  - Read hardware (`0xAA 0x04`) and firmware (`0xAA 0x05`) versions.
- **Web Dashboard:**
  - Rename probes, pick USDA meat/BBQ pit presets, set custom Low/High limits, view rolling sparklines, toggle browser WebAudio alerts, and inspect raw BLE/GATT frames in a live event log.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python h5055_monitor.py
```

Then open `http://localhost:8055` on your desktop or `http://<desktop-lan-ip>:8055` on your phone.

### CLI Options

```text
python h5055_monitor.py [--address XX:XX:XX:XX:XX:XX] [--port 8055]
```
If `--address` (or `GOVEE_H5055_MAC`) is omitted, the monitor auto-discovers the first H5055 that advertises within range.

## Reverse-Engineered H5055 Protocol Summary

### 1. Passive BLE Advertisement (`Service UUID 00005550-0000-1000-8000-00805f9b34fb`)
- **Manufacturer Data:** 2-byte company key (last 2 bytes of MAC) + 20-byte payload (`data[0..19]`), transmitted every `1.536s`:
  - `data[2] & 0x7F`: Battery percentage (`0–100%`)
  - `data[3] & 0x3F`: 6-bit bitmask of currently plugged-in probes (`P1=0x01 .. P6=0x20`)
  - `data[3] & 0xC0`: Probe pair carried in this beacon (`0x00` = P1/P2, `0x40` = P3/P4, `0x80` = P5/P6)
  - `data[4]` & `data[11]`: Marker bytes (`0x20` / `0x06` / `0x22`)
  - `struct.unpack("<hhhchhh", data[5:18])`: `(temp_1, min_1, max_1, sep, temp_2, min_2, max_2)` in whole `°C` (`-1` / `0xFFFF` when unset).

### 2. Active GATT Protocol
- **Service:** `00010203-0405-0607-0809-0a0b0c0d1910`
  - **Notify Characteristic:** `00010203-0405-0607-0809-0a0b0c0d2b10`
  - **Write Characteristic:** `00010203-0405-0607-0809-0a0b0c0d2b11` (`write-without-response`)
- **Frame Format:** 20 bytes `[dir, cmd, payload..., xor_checksum]`, where `dir` is `0xAA` (read/query) or `0x33` (write/set), and `pkt[19] = pkt[0] ^ ... ^ pkt[18]`.
- **Registers:**
  - `0xAA 0x07`: Returns `[0xAA, 0x07, plugged_mask, 0x00, lcd_unit, <6h probe_temps_c>, 0x00, 0x00, xor]`.
  - `0xAA 0x01 <probe 1..6>`: Returns `[0xAA, 0x01, probe, lcd_unit, <h high_c>, <h low_c>, ...]`.
  - `0x33 0x01 <probe 1..6> <h high_c> <h low_c>`: Sets hardware High/Low alarm thresholds in `°C` (or `[probe, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]` to disable).
  - `0x33 0x03 <unit>` / `0xAA 0x03`: Sets/reads the physical LCD display unit (`0x00` = `°F`, `0x01` = `°C`).
  - `0xAA 0x04` / `0xAA 0x05`: ASCII hardware (`1.00.03`) and firmware (`1.00.07`) version strings.
