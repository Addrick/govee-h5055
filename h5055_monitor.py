import argparse
import asyncio
import json
import os
import socket
import struct
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
from bleak import BleakClient, BleakScanner

PACKET_FMT = struct.Struct("<hhhchhh")
GATT_SIX_PROBES_FMT = struct.Struct("<6h")
GATT_ALARM_FMT = struct.Struct("<hh")

C_NOTIFY = "00010203-0405-0607-0809-0a0b0c0d2b10"
C_WRITE = "00010203-0405-0607-0809-0a0b0c0d2b11"
H5055_UUID = "00005550-0000-1000-8000-00805f9b34fb"

PROBE_PAIRS = {
    0x00: ((1, 0x01), (2, 0x02)),
    0x40: ((3, 0x04), (4, 0x08)),
    0x80: ((5, 0x10), (6, 0x20)),
}
ALL_PROBE_MASKS = {1: 0x01, 2: 0x02, 3: 0x04, 4: 0x08, 5: 0x10, 6: 0x20}

DEFAULT_PORT = 8055
MAX_HISTORY_POINTS = 360
MAX_EVENTS = 120


def make_gatt_cmd(b0: int, b1: int, payload: list[int] | bytes | None = None) -> bytes:
    pkt = bytearray(20)
    pkt[0] = b0
    pkt[1] = b1
    if payload:
        for i, val in enumerate(payload[:17]):
            pkt[2 + i] = val & 0xFF
    xor = 0
    for b in pkt[:19]:
        xor ^= b
    pkt[19] = xor
    return bytes(pkt)


QUERY_PROBES = make_gatt_cmd(0xAA, 0x07)
QUERY_HW_VER = make_gatt_cmd(0xAA, 0x04)
QUERY_FW_VER = make_gatt_cmd(0xAA, 0x05)
QUERY_UNIT = make_gatt_cmd(0xAA, 0x03)

state = {
    "address": os.environ.get("GOVEE_H5055_MAC"),
    "mode": "Scanning...",
    "gatt_enabled": True,
    "poll_interval_s": 1.0,
    "device_unit": None,  # 0 = °F, 1 = °C from 0xAA03 / 0xAA07[4]
    "hw_version": None,
    "fw_version": None,
    "rssi": None,
    "battery": None,
    "last_seen": None,
    "plugged_mask": 0,
    "probes": {},  # probe_num -> {"temp_c": float, "temp_f": float, "updated_at": float}
    "device_alarms": {
        i: {"high_c": None, "low_c": None, "high_f": None, "low_f": None, "raw": ""}
        for i in range(1, 7)
    },
    "history": {i: deque(maxlen=MAX_HISTORY_POINTS) for i in range(1, 7)},
    "events": deque(maxlen=MAX_EVENTS),
    "pending_cmds": deque(),
}
wake_gatt_event: asyncio.Event | None = None


def c_to_f(c: float) -> float:
    return round(c * 9.0 / 5.0 + 32.0, 1)


async def ensure_bluetooth_on() -> None:
    if sys.platform != "win32":
        return
    try:
        from winrt.windows.devices.radios import Radio, RadioKind, RadioState

        for radio in await Radio.get_radios_async():
            if radio.kind == RadioKind.BLUETOOTH and radio.state != RadioState.ON:
                await radio.set_state_async(RadioState.ON)
                print("Enabled Windows Bluetooth radio.", flush=True)
    except Exception:
        pass


def push_event(kind: str, detail: str, raw_hex: str = "", rssi: int | None = None):
    now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = {
        "time": now_str,
        "kind": kind,
        "rssi": rssi,
        "detail": detail,
        "hex": raw_hex,
    }
    state["events"].appendleft(entry)
    print(f"[{now_str}] [{kind.upper()}] (RSSI {rssi}) {detail} {raw_hex}", flush=True)


def update_device_alarm_state(probe_num: int, high_c: int, low_c: int, raw_hex: str = ""):
    hc = None if high_c <= 0 or high_c >= 500 else float(high_c)
    lc = None if low_c < 0 or low_c >= 500 else float(low_c)
    state["device_alarms"][probe_num] = {
        "high_c": hc,
        "low_c": lc,
        "high_f": c_to_f(hc) if hc is not None else None,
        "low_f": c_to_f(lc) if lc is not None else None,
        "raw": raw_hex,
    }


def ble_callback(device, adv):
    has_h5055_mfg = any(
        k != 76
        and len(v) == 20
        and v[4] in (0x06, 0x20, 0x22)
        and v[11] in (0x06, 0x20, 0x22)
        for k, v in adv.manufacturer_data.items()
    )
    is_target = (
        (state["address"] and device.address.upper() == state["address"].upper())
        or H5055_UUID in adv.service_uuids
        or has_h5055_mfg
    )
    if not is_target:
        return

    try:
        _, raw_data = adv.platform_data
        adv_ts = raw_data.adv.timestamp if raw_data.adv else None
        scan_ts = raw_data.scan.timestamp if raw_data.scan else None
        if scan_ts and (not adv_ts or scan_ts > adv_ts):
            scan_mfg = {
                m.company_id: bytes(m.data).hex()
                for m in raw_data.scan.advertisement.manufacturer_data
            }
            push_event(
                "skip",
                f"SCAN_RSP packet (iBeacon/UUID only, keys={list(scan_mfg.keys())})",
                "",
                adv.rssi,
            )
            return
    except Exception:
        pass

    non_apple = {k: v for k, v in adv.manufacturer_data.items() if k != 76}
    if not non_apple:
        return

    for company_id, data in non_apple.items():
        raw_hex = data.hex()
        if len(data) != 20:
            push_event("fail", f"Len check failed: len={len(data)}", raw_hex, adv.rssi)
            continue
        if data[4] not in (0x06, 0x20, 0x22) or data[11] not in (0x06, 0x20, 0x22):
            push_event(
                "fail",
                f"Marker check failed: byte4=0x{data[4]:02x} byte11=0x{data[11]:02x}",
                raw_hex,
                adv.rssi,
            )
            continue

        battery = int(data[2] & 0x7F)
        sensor_ids = data[3]
        plugged_mask = sensor_ids & 0x3F
        pair_bits = sensor_ids & 0xC0
        pair = PROBE_PAIRS.get(pair_bits)
        p1, min1, max1, _, p2, min2, max2 = PACKET_FMT.unpack(data[5:18])

        plugged_list = [p for p, m in ALL_PROBE_MASKS.items() if plugged_mask & m]
        if not pair:
            push_event(
                "fail",
                f"Unknown pair bits 0x{pair_bits:02x} (byte3=0x{sensor_ids:02x})",
                raw_hex,
                adv.rssi,
            )
            continue

        pair_names = f"P{pair[0][0]}/P{pair[1][0]}"
        readings = {}
        for (probe_num, mask), (temp, tmin, tmax) in zip(
            pair, ((p1, min1, max1), (p2, min2, max2))
        ):
            update_device_alarm_state(probe_num, tmax, tmin, raw_hex)
            if (plugged_mask & mask) and temp >= -40 and temp != -1:
                readings[probe_num] = {
                    "temp_c": float(temp),
                    "temp_f": c_to_f(float(temp)),
                    "updated_at": time.time(),
                }

        now_ts = time.time()
        first_discovery = state["address"] is None
        state["address"] = device.address
        state["rssi"] = adv.rssi
        state["battery"] = battery
        state["last_seen"] = now_ts
        state["plugged_mask"] = plugged_mask
        if first_discovery and wake_gatt_event is not None:
            wake_gatt_event.set()

        for p, mask in ALL_PROBE_MASKS.items():
            if not (plugged_mask & mask):
                state["probes"].pop(p, None)

        for p, info in readings.items():
            state["probes"][p] = info
            hist = state["history"][p]
            if not hist or (now_ts - hist[-1][0]) >= 2.0 or hist[-1][1] != info["temp_f"]:
                hist.append((now_ts, info["temp_f"], info["temp_c"]))

        if readings:
            summary = ", ".join(
                f"P{p}={r['temp_f']:.0f}°F/{r['temp_c']:.0f}°C" for p, r in readings.items()
            )
            push_event(
                "ok",
                f"Adv {pair_names} (byte3=0x{sensor_ids:02x}, plugged={plugged_list}): {summary}",
                raw_hex,
                adv.rssi,
            )
        else:
            push_event(
                "pair_miss",
                f"Adv {pair_names} (byte3=0x{sensor_ids:02x}) carries {pair_names}, plugged={plugged_list or 'none'}",
                raw_hex,
                adv.rssi,
            )


def on_gatt_notify(sender, data: bytearray):
    raw_bytes = bytes(data)
    raw_hex = raw_bytes.hex()
    if len(raw_bytes) != 20:
        return
    if raw_bytes[:2] == b"\xaa\x04":
        state["hw_version"] = raw_bytes[2:10].rstrip(b"\x00").decode("ascii", errors="ignore")
        return
    if raw_bytes[:2] == b"\xaa\x05":
        state["fw_version"] = raw_bytes[2:10].rstrip(b"\x00").decode("ascii", errors="ignore")
        return
    if raw_bytes[:2] == b"\xaa\x03":
        state["device_unit"] = int(raw_bytes[2])
        return
    if raw_bytes[:2] == b"\x33\x03":
        push_event("ok", "Thermometer ACKed LCD display unit change (0x3303)", raw_hex, state["rssi"])
        return
    if raw_bytes[:2] == b"\x33\x01":
        push_event("ok", "Thermometer ACKed probe alarm threshold write (0x3301)", raw_hex, state["rssi"])
        return
    if raw_bytes[:2] == b"\xaa\x01":
        probe_num = int(raw_bytes[2])
        if 1 <= probe_num <= 6:
            high_c, low_c = GATT_ALARM_FMT.unpack(raw_bytes[4:8])
            update_device_alarm_state(probe_num, high_c, low_c, raw_hex)
            da = state["device_alarms"][probe_num]
            push_event(
                "ok",
                f"Read P{probe_num} device alarm (0xAA01): High={da['high_f'] or 'Off'}°F, Low={da['low_f'] or 'Off'}°F",
                raw_hex,
                state["rssi"],
            )
        return
    if raw_bytes[:2] == b"\xaa\x07":
        plugged_mask = raw_bytes[2] & 0x3F
        state["device_unit"] = int(raw_bytes[4])
        temps = GATT_SIX_PROBES_FMT.unpack(raw_bytes[5:17])
        now_ts = time.time()
        state["last_seen"] = now_ts
        state["plugged_mask"] = plugged_mask
        state["mode"] = "GATT Connected"

        for p, mask in ALL_PROBE_MASKS.items():
            if not (plugged_mask & mask):
                state["probes"].pop(p, None)

        readings = {}
        for p in range(1, 7):
            mask = ALL_PROBE_MASKS[p]
            temp = temps[p - 1]
            if (plugged_mask & mask) and temp >= -40 and temp != -1:
                info = {
                    "temp_c": float(temp),
                    "temp_f": c_to_f(float(temp)),
                    "updated_at": now_ts,
                }
                readings[p] = info
                state["probes"][p] = info
                hist = state["history"][p]
                if not hist or (now_ts - hist[-1][0]) >= 1.0 or hist[-1][1] != info["temp_f"]:
                    hist.append((now_ts, info["temp_f"], info["temp_c"]))

        plugged_list = [p for p, m in ALL_PROBE_MASKS.items() if plugged_mask & m]
        summary = (
            ", ".join(f"P{p}={r['temp_f']:.0f}°F/{r['temp_c']:.0f}°C" for p, r in readings.items())
            or "none"
        )
        push_event(
            "ok",
            f"GATT 0xAA07 (all 6 slots, plugged={plugged_list}): {summary} | raw_6={temps}",
            raw_hex,
            state["rssi"],
        )


def build_probe_alarm_cmd(probe_num: int, high_c: int | None, low_c: int | None) -> bytes:
    if high_c is None and low_c is None:
        return make_gatt_cmd(0x33, 0x01, [probe_num, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
    h_val = int(high_c) if high_c is not None else -1
    l_val = int(low_c) if low_c is not None else -1
    packed = GATT_ALARM_FMT.pack(h_val, l_val)
    return make_gatt_cmd(0x33, 0x01, [probe_num] + list(packed))


async def gatt_poll_loop():
    global wake_gatt_event
    wake_gatt_event = asyncio.Event()
    while True:
        addr = state.get("address")
        if not addr or not state["gatt_enabled"] or state["poll_interval_s"] <= 0:
            state["mode"] = "BLE Adv" if addr else "Scanning..."
            await asyncio.sleep(1.0)
            continue
        try:
            async with BleakClient(addr, timeout=8.0) as client:
                state["mode"] = "GATT Connected"
                push_event(
                    "ok",
                    f"GATT connected to {addr}; reading device registers & polling all 6 probes",
                    "",
                    state["rssi"],
                )
                await client.start_notify(C_NOTIFY, on_gatt_notify)
                for init_q in (QUERY_HW_VER, QUERY_FW_VER, QUERY_UNIT):
                    await client.write_gatt_char(C_WRITE, init_q, response=False)
                    await asyncio.sleep(0.06)
                for p in range(1, 7):
                    await client.write_gatt_char(
                        C_WRITE, make_gatt_cmd(0xAA, 0x01, [p]), response=False
                    )
                    await asyncio.sleep(0.06)

                while client.is_connected and state["gatt_enabled"] and state["poll_interval_s"] > 0:
                    while state["pending_cmds"]:
                        cmd_bytes = state["pending_cmds"].popleft()
                        await client.write_gatt_char(C_WRITE, cmd_bytes, response=False)
                        await asyncio.sleep(0.08)
                    await client.write_gatt_char(C_WRITE, QUERY_PROBES, response=False)
                    wake_gatt_event.clear()
                    try:
                        await asyncio.wait_for(
                            wake_gatt_event.wait(), timeout=state["poll_interval_s"]
                        )
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            state["mode"] = "BLE Adv"
            await asyncio.sleep(2.0)


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Govee H5055 Controller</title>
<style>
  :root {
    --bg: #0f172a;
    --card: #1e293b;
    --card-inner: #0f172a;
    --border: #334155;
    --text: #f8fafc;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --ok: #22c55e;
    --warn: #f59e0b;
    --alert: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 16px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
  }
  header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    max-width: 1080px;
    margin: 0 auto 18px auto;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }
  h1 { margin: 0; font-size: 1.35rem; }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .pill {
    background: var(--card);
    border: 1px solid var(--border);
    padding: 5px 10px;
    border-radius: 999px;
  }
  button.unit-btn, select.interval-select {
    background: var(--card);
    color: var(--text);
    border: 1px solid var(--accent);
    border-radius: 8px;
    padding: 6px 11px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.84rem;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 16px;
    max-width: 1080px;
    margin: 0 auto;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 15px;
    transition: border-color 0.2s, opacity 0.2s;
  }
  .card.unplugged {
    opacity: 0.6;
  }
  .card.alerting {
    border-color: var(--alert);
    box-shadow: 0 0 18px rgba(239, 68, 68, 0.45);
  }
  .probe-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: 0.85rem;
    font-weight: 700;
  }
  .probe-name-input {
    background: transparent;
    border: 1px dashed transparent;
    color: var(--text);
    font-weight: 700;
    font-size: 0.95rem;
    padding: 2px 6px;
    border-radius: 5px;
    width: 170px;
  }
  .probe-name-input:hover, .probe-name-input:focus {
    border-color: var(--border);
    background: var(--card-inner);
    outline: none;
  }
  .temp-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin: 8px 0 4px 0;
  }
  .temp-main {
    font-size: 2.6rem;
    font-weight: 700;
    letter-spacing: -1px;
  }
  .temp-sub {
    color: var(--muted);
    font-size: 0.9rem;
  }
  svg.spark {
    width: 100%;
    height: 42px;
    display: block;
    margin: 6px 0 10px 0;
  }
  .alarm-box {
    background: var(--card-inner);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    margin-top: 8px;
    font-size: 0.82rem;
  }
  .alarm-box-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
    color: var(--muted);
    font-weight: 600;
  }
  .device-badge {
    font-size: 0.75rem;
    padding: 2px 7px;
    border-radius: 999px;
    background: rgba(56, 189, 248, 0.14);
    color: var(--accent);
  }
  .preset-select {
    width: 100%;
    background: var(--card);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 0.82rem;
    margin-bottom: 8px;
  }
  .limits-row {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }
  .limit-field {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .limit-field label {
    font-size: 0.74rem;
    color: var(--muted);
  }
  .limit-field input {
    width: 100%;
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 0.88rem;
  }
  .alarm-actions {
    display: flex;
    gap: 6px;
    justify-content: flex-end;
  }
  .log-panel, .settings-panel {
    max-width: 1080px;
    margin: 20px auto 0 auto;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px 16px;
  }
  .settings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(235px, 1fr));
    gap: 12px;
    margin-top: 10px;
  }
  .setting-item {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .setting-label {
    font-size: 0.75rem;
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
  }
  .setting-value {
    font-size: 0.9rem;
    font-weight: 600;
    display: flex;
    gap: 6px;
    align-items: center;
    flex-wrap: wrap;
  }
  .btn-sm {
    background: var(--card);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 10px;
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 600;
  }
  .btn-sm:hover { border-color: var(--accent); }
  .btn-sm.active {
    border-color: var(--accent);
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent);
  }
  .btn-sm.primary {
    border-color: var(--accent);
    background: rgba(56, 189, 248, 0.2);
    color: #e0f2fe;
  }
  .log-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
    font-size: 0.88rem;
    font-weight: 600;
    color: var(--muted);
  }
  .log-list {
    max-height: 280px;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 0.77rem;
    line-height: 1.45;
  }
  .log-row {
    padding: 4px 6px;
    border-bottom: 1px solid rgba(51, 65, 85, 0.5);
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .badge {
    padding: 1px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.72rem;
  }
  .badge.ok { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
  .badge.pair_miss { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
  .badge.skip { background: rgba(148, 163, 184, 0.2); color: #94a3b8; }
  .badge.fail { background: rgba(239, 68, 68, 0.25); color: #f87171; }
  .hex-str { color: #64748b; }
</style>
</head>
<body>
<header>
  <div>
    <h1>Govee H5055 Controller</h1>
  </div>
  <div class="meta">
    <span class="pill" id="mode-pill">Mode: --</span>
    <span class="pill" id="status-pill">Waiting for BLE...</span>
    <span class="pill" id="battery-pill">Bat: --%</span>
    <span class="pill" id="rssi-pill">RSSI: -- dBm</span>
    <select class="interval-select" id="interval-select" onchange="changeInterval(this.value)" title="Poll / Refresh Interval">
      <option value="1000">Refresh: 1s</option>
      <option value="2000">Refresh: 2s</option>
      <option value="5000">Refresh: 5s</option>
      <option value="10000">Refresh: 10s</option>
      <option value="30000">Refresh: 30s</option>
      <option value="60000">Refresh: 60s</option>
      <option value="0">Refresh: Off</option>
    </select>
    <button class="unit-btn" id="unit-toggle" onclick="toggleUnit()">Unit: °F</button>
    <button class="unit-btn" onclick="toggleSettings()">Settings</button>
  </div>
</header>

<div class="settings-panel" id="settings-panel" style="display:block; margin-bottom:20px;">
  <div class="log-header">
    <span>THERMOMETER & APP SETTINGS</span>
    <span id="dev-info-str" style="font-weight:normal;">HW: -- | FW: -- | MAC: --</span>
  </div>
  <div class="settings-grid">
    <div class="setting-item">
      <span class="setting-label">Thermometer LCD Screen Unit (0x3303)</span>
      <div class="setting-value">
        <button class="btn-sm" id="lcd-unit-0" onclick="sendConfig({lcd_unit: 0})">°F on LCD (0x00)</button>
        <button class="btn-sm" id="lcd-unit-1" onclick="sendConfig({lcd_unit: 1})">°C on LCD (0x01)</button>
      </div>
    </div>
    <div class="setting-item">
      <span class="setting-label">Device Hardware Alarms (0x3301)</span>
      <div class="setting-value">
        <button class="btn-sm" onclick="sendConfig({read_alarms: 1})">Read Device Alarms</button>
        <button class="btn-sm" onclick="sendConfig({clear_all_alarms: 1})">Clear All P1–P6 Alarms</button>
      </div>
    </div>
    <div class="setting-item">
      <span class="setting-label">BLE Acquisition Mode</span>
      <div class="setting-value">
        <button class="btn-sm" id="mode-gatt" onclick="sendConfig({gatt: 1})">Active GATT (1s Direct)</button>
        <button class="btn-sm" id="mode-adv" onclick="sendConfig({gatt: 0})">Passive Broadcast</button>
      </div>
    </div>
    <div class="setting-item">
      <span class="setting-label">Web UI & Diagnostics</span>
      <div class="setting-value">
        <button class="btn-sm" id="audio-btn" onclick="toggleAudio()">Browser Beep: Off</button>
        <button class="btn-sm" onclick="sendConfig({clear_history: 1})">Clear Charts</button>
        <button class="btn-sm" onclick="sendConfig({clear_events: 1})">Clear Log</button>
      </div>
    </div>
  </div>
</div>

<div class="grid" id="probes-grid"></div>

<div class="log-panel">
  <div class="log-header">
    <span>BLE & GATT EVENT LOG (NEWEST FIRST)</span>
    <label style="font-weight:normal;cursor:pointer;">
      <input type="checkbox" id="show-scan-rsp" onchange="fetchState()" /> Show SCAN_RSP frames
    </label>
  </div>
  <div class="log-list" id="event-log"></div>
</div>

<script>
const PRESETS = [
  { label: "Custom / Manual", lowC: null, highC: null },
  { label: "Beef — Rare (125°F / 52°C)", lowC: null, highC: 52 },
  { label: "Beef — Med Rare (135°F / 57°C)", lowC: null, highC: 57 },
  { label: "Beef — Medium (145°F / 63°C)", lowC: null, highC: 63 },
  { label: "Beef — Well Done (160°F / 71°C)", lowC: null, highC: 71 },
  { label: "Beef Brisket / BBQ (203°F / 95°C)", lowC: null, highC: 95 },
  { label: "Pork — Medium (145°F / 63°C)", lowC: null, highC: 63 },
  { label: "Pork — Well Done (160°F / 71°C)", lowC: null, highC: 71 },
  { label: "Pork — Pulled (203°F / 95°C)", lowC: null, highC: 95 },
  { label: "Chicken / Turkey Breast (165°F / 74°C)", lowC: null, highC: 74 },
  { label: "Poultry Dark / Thigh (175°F / 79°C)", lowC: null, highC: 79 },
  { label: "Lamb — Med Rare (135°F / 57°C)", lowC: null, highC: 57 },
  { label: "Fish (145°F / 63°C)", lowC: null, highC: 63 },
  { label: "BBQ Pit / Smoker (215–250°F / 102–121°C)", lowC: 102, highC: 121 },
  { label: "Cold Smoker / Fridge (34–40°F / 1–4°C)", lowC: 1, highC: 4 }
];

let unit = localStorage.getItem('h5055_unit') || 'F';
let refreshMs = Number(localStorage.getItem('h5055_refresh_ms') ?? 1000);
let audioEnabled = localStorage.getItem('h5055_audio') === '1';
let probeNames = JSON.parse(localStorage.getItem('h5055_names') || '{}');
let probeDrafts = JSON.parse(localStorage.getItem('h5055_drafts') || '{}');
let pollTimer = null;
let inFlight = false;
let lastSeenClientMs = null;

function cToF(c) { return Math.round(c * 9 / 5 + 32); }
function fToC(f) { return Math.round((f - 32) * 5 / 9); }

function updateStatusPill() {
  const statusEl = document.getElementById('status-pill');
  if (!lastSeenClientMs) return;
  const ago = Math.max(0, Math.round((Date.now() - lastSeenClientMs) / 1000));
  statusEl.textContent = ago < 10 ? `Live (${ago}s ago)` : `Stale (${ago}s ago)`;
  statusEl.style.borderColor = ago < 10 ? '#22c55e' : '#f59e0b';
}
setInterval(updateStatusPill, 1000);

function scheduleNext() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  if (refreshMs > 0) {
    pollTimer = setTimeout(fetchState, refreshMs);
  }
}

function changeInterval(val) {
  refreshMs = Number(val);
  localStorage.setItem('h5055_refresh_ms', String(refreshMs));
  fetch('/api/interval?ms=' + refreshMs).catch(() => {});
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  if (refreshMs > 0) fetchState();
}

function toggleSettings() {
  const el = document.getElementById('settings-panel');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function toggleAudio() {
  audioEnabled = !audioEnabled;
  localStorage.setItem('h5055_audio', audioEnabled ? '1' : '0');
  document.getElementById('audio-btn').textContent = 'Browser Beep: ' + (audioEnabled ? 'On' : 'Off');
  document.getElementById('audio-btn').className = 'btn-sm' + (audioEnabled ? ' active' : '');
}

function beep() {
  if (!audioEnabled) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 880;
    gain.gain.value = 0.08;
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    setTimeout(() => { osc.stop(); ctx.close(); }, 180);
  } catch (e) {}
}

async function sendConfig(params) {
  const qs = new URLSearchParams(params).toString();
  await fetch('/api/config?' + qs).catch(() => {});
  fetchState();
}

function toggleUnit() {
  unit = unit === 'F' ? 'C' : 'F';
  localStorage.setItem('h5055_unit', unit);
  document.getElementById('unit-toggle').textContent = 'Unit: °' + unit;
  for (let p = 1; p <= 6; p++) {
    const lowIn = document.getElementById(`low-in-${p}`);
    const highIn = document.getElementById(`high-in-${p}`);
    if (lowIn && lowIn.value !== '') {
      const v = Number(lowIn.value);
      lowIn.value = unit === 'F' ? cToF(v) : fToC(v);
    }
    if (highIn && highIn.value !== '') {
      const v = Number(highIn.value);
      highIn.value = unit === 'F' ? cToF(v) : fToC(v);
    }
    saveDraft(p);
  }
  fetchState();
}

function saveProbeName(p, val) {
  probeNames[p] = val;
  localStorage.setItem('h5055_names', JSON.stringify(probeNames));
}

function saveDraft(p) {
  const lowVal = document.getElementById(`low-in-${p}`).value;
  const highVal = document.getElementById(`high-in-${p}`).value;
  const presetVal = document.getElementById(`preset-${p}`).value;
  probeDrafts[p] = { low: lowVal, high: highVal, preset: presetVal };
  localStorage.setItem('h5055_drafts', JSON.stringify(probeDrafts));
}

function applyPreset(p, idx) {
  const preset = PRESETS[Number(idx)];
  if (!preset) return;
  const lowIn = document.getElementById(`low-in-${p}`);
  const highIn = document.getElementById(`high-in-${p}`);
  if (preset.lowC != null) {
    lowIn.value = unit === 'F' ? cToF(preset.lowC) : preset.lowC;
  } else if (Number(idx) > 0) {
    lowIn.value = '';
  }
  if (preset.highC != null) {
    highIn.value = unit === 'F' ? cToF(preset.highC) : preset.highC;
  }
  saveDraft(p);
}

async function syncProbeAlarmToDevice(p) {
  saveDraft(p);
  const lowStr = document.getElementById(`low-in-${p}`).value;
  const highStr = document.getElementById(`high-in-${p}`).value;
  let lowC = '';
  let highC = '';
  if (lowStr !== '' && !isNaN(Number(lowStr))) {
    lowC = unit === 'F' ? fToC(Number(lowStr)) : Math.round(Number(lowStr));
  }
  if (highStr !== '' && !isNaN(Number(highStr))) {
    highC = unit === 'F' ? fToC(Number(highStr)) : Math.round(Number(highStr));
  }
  await sendConfig({ set_alarm_probe: p, high_c: highC, low_c: lowC });
}

async function clearProbeAlarm(p) {
  document.getElementById(`low-in-${p}`).value = '';
  document.getElementById(`high-in-${p}`).value = '';
  document.getElementById(`preset-${p}`).value = '0';
  saveDraft(p);
  await sendConfig({ set_alarm_probe: p, high_c: '', low_c: '' });
}

function makeSparkline(points) {
  if (!points || points.length < 2) return '';
  const vals = points.map(p => unit === 'F' ? p[1] : p[2]);
  const min = Math.min(...vals) - 1;
  const max = Math.max(...vals) + 1;
  const w = 260, h = 42;
  const coords = vals.map((v, i) => {
    const x = (i / (vals.length - 1)) * w;
    const y = h - ((v - min) / (max - min || 1)) * (h - 8) - 4;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <polyline fill="none" stroke="#38bdf8" stroke-width="2" points="${coords}" />
  </svg>`;
}

function initGrid() {
  const grid = document.getElementById('probes-grid');
  const presetOpts = PRESETS.map((pr, i) => `<option value="${i}">${pr.label}</option>`).join('');
  let html = '';
  for (let p = 1; p <= 6; p++) {
    const customName = probeNames[p] || `Probe ${p}`;
    const draft = probeDrafts[p] || { low: '', high: '', preset: '0' };
    html += `
      <div class="card unplugged" id="card-${p}">
        <div class="probe-header">
          <input class="probe-name-input" id="name-${p}" value="${customName}" oninput="saveProbeName(${p}, this.value)" title="Click to rename probe" />
          <span id="state-${p}">UNPLUGGED</span>
        </div>
        <div class="temp-row">
          <div class="temp-main" id="main-${p}">--°${unit}</div>
          <div class="temp-sub" id="sub-${p}">No probe</div>
        </div>
        <div id="spark-${p}"></div>
        <div class="alarm-box">
          <div class="alarm-box-header">
            <span>ALERT THRESHOLDS</span>
            <span class="device-badge" id="dev-alarm-${p}">Device: Off</span>
          </div>
          <select class="preset-select" id="preset-${p}" onchange="applyPreset(${p}, this.value)">
            ${presetOpts}
          </select>
          <div class="limits-row">
            <div class="limit-field">
              <label id="low-lbl-${p}">Low Alert (°${unit})</label>
              <input type="number" id="low-in-${p}" value="${draft.low || ''}" placeholder="Off" oninput="saveDraft(${p})" />
            </div>
            <div class="limit-field">
              <label id="high-lbl-${p}">High Alert (°${unit})</label>
              <input type="number" id="high-in-${p}" value="${draft.high || ''}" placeholder="Off" oninput="saveDraft(${p})" />
            </div>
          </div>
          <div class="alarm-actions">
            <button class="btn-sm primary" onclick="syncProbeAlarmToDevice(${p})" title="Write High/Low alarm limits to H5055 hardware (0x3301)">Sync to Device</button>
            <button class="btn-sm" onclick="clearProbeAlarm(${p})" title="Clear High/Low alarm on H5055 hardware">Clear</button>
          </div>
        </div>
      </div>`;
  }
  grid.innerHTML = html;
  for (let p = 1; p <= 6; p++) {
    const draft = probeDrafts[p];
    if (draft && draft.preset) {
      document.getElementById(`preset-${p}`).value = draft.preset;
    }
  }
}

function render(data) {
  document.getElementById('unit-toggle').textContent = 'Unit: °' + unit;
  document.getElementById('mode-pill').textContent = `Mode: ${data.mode || '--'}`;
  document.getElementById('mode-gatt').className = 'btn-sm' + (data.gatt_enabled ? ' active' : '');
  document.getElementById('mode-adv').className = 'btn-sm' + (!data.gatt_enabled ? ' active' : '');
  document.getElementById('lcd-unit-0').className = 'btn-sm' + (data.device_unit === 0 ? ' active' : '');
  document.getElementById('lcd-unit-1').className = 'btn-sm' + (data.device_unit === 1 ? ' active' : '');
  document.getElementById('audio-btn').textContent = 'Browser Beep: ' + (audioEnabled ? 'On' : 'Off');
  document.getElementById('audio-btn').className = 'btn-sm' + (audioEnabled ? ' active' : '');
  document.getElementById('dev-info-str').textContent =
    `HW: ${data.hw_version || '--'} | FW: ${data.fw_version || '--'} | MAC: ${data.address || '--'}`;

  if (data.last_seen) {
    const serverAgeMs = Math.max(0, (data.now - data.last_seen) * 1000);
    lastSeenClientMs = Date.now() - serverAgeMs;
    updateStatusPill();
  }
  document.getElementById('battery-pill').textContent = data.battery != null ? `Bat: ${data.battery}%` : 'Bat: --%';
  document.getElementById('rssi-pill').textContent = data.rssi != null ? `RSSI: ${data.rssi} dBm` : 'RSSI: -- dBm';

  let anyAlerting = false;
  for (let p = 1; p <= 6; p++) {
    const info = data.probes[p];
    const hist = data.history[p] || [];
    const devAlarm = (data.device_alarms && data.device_alarms[p]) || {};
    const card = document.getElementById(`card-${p}`);
    const stateSpan = document.getElementById(`state-${p}`);
    const mainEl = document.getElementById(`main-${p}`);
    const subEl = document.getElementById(`sub-${p}`);
    const sparkEl = document.getElementById(`spark-${p}`);
    const devBadge = document.getElementById(`dev-alarm-${p}`);

    document.getElementById(`low-lbl-${p}`).textContent = `Low Alert (°${unit})`;
    document.getElementById(`high-lbl-${p}`).textContent = `High Alert (°${unit})`;

    const devHigh = unit === 'F' ? devAlarm.high_f : devAlarm.high_c;
    const devLow = unit === 'F' ? devAlarm.low_f : devAlarm.low_c;
    if (devHigh != null || devLow != null) {
      const parts = [];
      if (devLow != null) parts.push(`L:${Math.round(devLow)}°${unit}`);
      if (devHigh != null) parts.push(`H:${Math.round(devHigh)}°${unit}`);
      devBadge.textContent = `Device: ${parts.join(' / ')}`;
    } else {
      devBadge.textContent = 'Device: Off';
    }

    const draft = probeDrafts[p] || {};
    const effLow = draft.low !== '' && draft.low != null ? Number(draft.low) : (devLow != null ? Number(devLow) : null);
    const effHigh = draft.high !== '' && draft.high != null ? Number(draft.high) : (devHigh != null ? Number(devHigh) : null);

    const isPlugged = Boolean((data.plugged_mask || 0) & (1 << (p - 1)));
    if (info) {
      const mainNum = unit === 'F' ? info.temp_f : info.temp_c;
      const mainVal = mainNum.toFixed(0);
      const altVal = unit === 'F' ? `${info.temp_c.toFixed(0)}°C` : `${info.temp_f.toFixed(0)}°F`;
      const isHighAlert = effHigh != null && !isNaN(effHigh) && mainNum >= effHigh;
      const isLowAlert = effLow != null && !isNaN(effLow) && mainNum <= effLow;
      const isAlert = isHighAlert || isLowAlert;
      if (isAlert) anyAlerting = true;

      card.className = `card ${isAlert ? 'alerting' : ''}`;
      stateSpan.textContent = isHighAlert ? 'HIGH ALERT' : (isLowAlert ? 'LOW ALERT' : 'ACTIVE');
      stateSpan.style.color = isAlert ? '#ef4444' : '#22c55e';
      mainEl.textContent = `${mainVal}°${unit}`;
      subEl.textContent = altVal;
      sparkEl.innerHTML = makeSparkline(hist);
    } else if (isPlugged) {
      card.className = 'card';
      stateSpan.textContent = 'SYNCING...';
      stateSpan.style.color = '#f59e0b';
      mainEl.textContent = `…°${unit}`;
      subEl.textContent = 'Waiting for slot';
      sparkEl.innerHTML = '';
    } else {
      card.className = 'card unplugged';
      stateSpan.textContent = 'UNPLUGGED';
      stateSpan.style.color = '';
      mainEl.textContent = `--°${unit}`;
      subEl.textContent = 'No probe';
      sparkEl.innerHTML = '';
    }
  }
  if (anyAlerting) beep();

  const showScanRsp = document.getElementById('show-scan-rsp').checked;
  const logEl = document.getElementById('event-log');
  const events = (data.events || []).filter(e => showScanRsp || e.kind !== 'skip');
  logEl.innerHTML = events.map(e => `
    <div class="log-row">
      <span style="color:#94a3b8">${e.time}</span>
      <span class="badge ${e.kind}">${e.kind.toUpperCase()}</span>
      <span style="color:#94a3b8">${e.rssi != null ? e.rssi + ' dBm' : ''}</span>
      <span>${e.detail}</span>
      ${e.hex ? `<span class="hex-str">[${e.hex}]</span>` : ''}
    </div>
  `).join('') || '<div style="color:#64748b;padding:8px;">No BLE events yet...</div>';
}

async function fetchState() {
  if (inFlight) return;
  inFlight = true;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 2000);
  try {
    const res = await fetch('/api/state', { signal: ctrl.signal, cache: 'no-store' });
    const data = await res.json();
    render(data);
  } catch (e) {
  } finally {
    clearTimeout(timer);
    inFlight = false;
    scheduleNext();
  }
}

initGrid();
document.getElementById('interval-select').value = String(refreshMs);
fetch('/api/interval?ms=' + refreshMs).catch(() => {});
fetchState();
</script>
</body>
</html>
"""


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        if not request_line:
            return
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not line or line in (b"\r\n", b"\n"):
                break
        parts = request_line.decode("utf-8", errors="ignore").split()
        raw_path = parts[1] if len(parts) >= 2 else "/"
        parsed_url = urlparse(raw_path)
        path = parsed_url.path

        if path == "/api/interval":
            qs = parse_qs(parsed_url.query)
            ms = int(qs.get("ms", ["1000"])[0])
            state["poll_interval_s"] = max(0.5, ms / 1000.0) if ms > 0 else 0.0
            if wake_gatt_event is not None:
                wake_gatt_event.set()
            payload = b'{"ok":true}'
            header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(header + payload)
        elif path == "/api/config":
            qs = parse_qs(parsed_url.query)
            if "gatt" in qs:
                state["gatt_enabled"] = qs["gatt"][0] == "1"
                if wake_gatt_event is not None:
                    wake_gatt_event.set()
            if "lcd_unit" in qs:
                u_val = int(qs["lcd_unit"][0]) & 0x01
                state["pending_cmds"].append(make_gatt_cmd(0x33, 0x03, [u_val]))
                state["pending_cmds"].append(QUERY_UNIT)
                if wake_gatt_event is not None:
                    wake_gatt_event.set()
            if "read_alarms" in qs:
                for p in range(1, 7):
                    state["pending_cmds"].append(make_gatt_cmd(0xAA, 0x01, [p]))
                if wake_gatt_event is not None:
                    wake_gatt_event.set()
            if "clear_all_alarms" in qs:
                for p in range(1, 7):
                    state["pending_cmds"].append(build_probe_alarm_cmd(p, None, None))
                    state["pending_cmds"].append(make_gatt_cmd(0xAA, 0x01, [p]))
                if wake_gatt_event is not None:
                    wake_gatt_event.set()
            if "set_alarm_probe" in qs:
                p = int(qs["set_alarm_probe"][0])
                if 1 <= p <= 6:
                    h_str = qs.get("high_c", [""])[0]
                    l_str = qs.get("low_c", [""])[0]
                    high_c = int(h_str) if h_str != "" else None
                    low_c = int(l_str) if l_str != "" else None
                    state["pending_cmds"].append(build_probe_alarm_cmd(p, high_c, low_c))
                    state["pending_cmds"].append(make_gatt_cmd(0xAA, 0x01, [p]))
                    if wake_gatt_event is not None:
                        wake_gatt_event.set()
            if "clear_history" in qs:
                for h in state["history"].values():
                    h.clear()
            if "clear_events" in qs:
                state["events"].clear()
            payload = b'{"ok":true}'
            header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(header + payload)
        elif path.startswith("/api/state"):
            payload = json.dumps(
                {
                    "now": time.time(),
                    "mode": state["mode"],
                    "gatt_enabled": state["gatt_enabled"],
                    "device_unit": state["device_unit"],
                    "hw_version": state["hw_version"],
                    "fw_version": state["fw_version"],
                    "address": state["address"],
                    "rssi": state["rssi"],
                    "battery": state["battery"],
                    "last_seen": state["last_seen"],
                    "plugged_mask": state["plugged_mask"],
                    "probes": state["probes"],
                    "device_alarms": state["device_alarms"],
                    "history": {k: list(v) for k, v in state["history"].items()},
                    "events": list(state["events"]),
                }
            ).encode("utf-8")
            header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Cache-Control: no-store\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(header + payload)
        else:
            body = INDEX_HTML.encode("utf-8")
            header = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Cache-Control: no-store\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(header + body)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def get_lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


async def main():
    parser = argparse.ArgumentParser(description="Local BLE/GATT web controller for Govee H5055")
    parser.add_argument("--address", help="Optional H5055 BLE MAC address (auto-discovers if omitted)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTP port (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    if args.address:
        state["address"] = args.address

    await ensure_bluetooth_on()
    server = await asyncio.start_server(handle_http, ["0.0.0.0", "::1"], args.port)
    lan_ip = get_lan_ip()
    print("Web UI running at:", flush=True)
    print(f"  Desktop: http://localhost:{args.port}", flush=True)
    print(f"  Phone (Wi-Fi): http://{lan_ip}:{args.port}", flush=True)
    print("Scanning for Govee H5055...", flush=True)

    scanner_kwargs = {}
    if sys.platform == "win32":
        try:
            from winrt.windows.devices.bluetooth import BluetoothSignalStrengthFilter

            sf = BluetoothSignalStrengthFilter()
            sf.sampling_interval = timedelta(seconds=0)
            sf.in_range_threshold_in_dbm = -127
            scanner_kwargs["SignalStrengthFilter"] = sf
        except Exception:
            pass

    gatt_task = asyncio.create_task(gatt_poll_loop())
    try:
        async with server, BleakScanner(
            ble_callback, scanning_mode="active", **scanner_kwargs
        ):
            await asyncio.Event().wait()
    finally:
        gatt_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
