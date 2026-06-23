"""
Tuya BLE transport — local control over Bluetooth.

Protocol reference: ha_tuya_ble (PlusPlus-ua/ha_tuya_ble on GitHub).
This implementation follows the same packet format, key derivation, and
authentication sequence used by that integration.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
import time
import weakref
from hashlib import md5
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from Crypto.Cipher import AES

_LOGGER = logging.getLogger(__name__)

# ── GATT UUIDs ────────────────────────────────────────────────────────────────
TUYA_BLE_SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
TUYA_BLE_WRITE_UUID   = "00002b11-0000-1000-8000-00805f9b34fb"
TUYA_BLE_NOTIFY_UUID  = "00002b10-0000-1000-8000-00805f9b34fb"

# ── Command codes ─────────────────────────────────────────────────────────────
class BLECmd:
    DEVICE_INFO   = 0x0000   # request / response
    PAIR          = 0x0001   # request / response
    DPS           = 0x0002   # send DP values to device
    DEVICE_STATUS = 0x0003   # request current DP state
    DP_REPORT     = 0x8001   # unsolicited DP push from device
    DP_REPORT_T   = 0x8003   # DP push with timestamp
    DP_REPORT_S   = 0x8004   # DP push signed
    DP_REPORT_ST  = 0x8005   # DP push signed + timestamp
    TIME1_REQ     = 0x8011   # device asking for Unix-ms timestamp
    TIME2_REQ     = 0x8012   # device asking for struct-time

# ── DP types (BLE encoding — different from WiFi protocol) ────────────────────
_DPT_RAW    = 0
_DPT_BOOL   = 1
_DPT_INT    = 2
_DPT_STR    = 3
_DPT_ENUM   = 4
_DPT_BITMAP = 5

TIMEOUT_CMD       = 12.0
HEARTBEAT_INTERVAL = 30.0
GATT_MTU          = 20


# ── Helpers ───────────────────────────────────────────────────────────────────

def _crc16(data: bytes) -> int:
    """CRC-16 MODBUS."""
    crc = 0xFFFF
    for b in data:
        crc ^= b & 0xFF
        for _ in range(8):
            tmp = crc & 1
            crc >>= 1
            if tmp:
                crc ^= 0xA001
    return crc


def _pack_varint(value: int) -> bytes:
    """LEB128 variable-length integer (used for BLE packet framing)."""
    result = bytearray()
    while True:
        curr = value & 0x7F
        value >>= 7
        if value:
            curr |= 0x80
        result.append(curr)
        if not value:
            break
    return bytes(result)


def _unpack_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    for offset in range(5):
        b = data[pos + offset]
        result |= (b & 0x7F) << (offset * 7)
        if not (b & 0x80):
            return result, pos + offset + 1
    raise ValueError("varint overflow")


def _build_packets(
    seq: int,
    code: int,
    payload: bytes,
    key: bytes,
    response_to: int = 0,
    security_flag: int = 0x05,
    protocol_version: int = 3,
) -> list[bytes]:
    """
    Build one or more MTU-sized BLE chunks for a Tuya BLE command.

    Wire format per chunk:
      [packet_num: varint]
      [if first: total_encrypted_len: varint + protocol_version_nibble: 1B]
      [data_bytes up to MTU]

    Encrypted blob:
      security_flag(1) + IV(16) + AES-CBC(key, IV, padded_raw)

    Raw (pre-encryption):
      seq(4) + response_to(4) + code(2) + data_len(2) + payload + CRC16(2) + padding
    """
    iv = secrets.token_bytes(16)

    raw = bytearray()
    raw += struct.pack(">IIHH", seq, response_to, code, len(payload))
    raw += payload
    raw += struct.pack(">H", _crc16(raw))
    while len(raw) % 16:
        raw += b"\x00"

    cipher    = AES.new(key, AES.MODE_CBC, iv)
    encrypted = bytes([security_flag]) + iv + cipher.encrypt(bytes(raw))

    packets   = []
    pkt_num   = 0
    pos       = 0
    total_len = len(encrypted)

    while pos < total_len:
        hdr = _pack_varint(pkt_num)
        if pkt_num == 0:
            hdr += _pack_varint(total_len)
            hdr += bytes([protocol_version << 4])
        chunk = encrypted[pos : pos + GATT_MTU - len(hdr)]
        packets.append(bytes(hdr) + chunk)
        pos     += len(chunk)
        pkt_num += 1

    return packets


def _parse_packet(raw_encrypted: bytes, key: bytes) -> tuple[int, int, int, bytes]:
    """
    Decrypt and parse a reassembled Tuya BLE blob.
    Returns (seq_num, response_to, code, payload).
    """
    iv         = raw_encrypted[1:17]
    ciphertext = raw_encrypted[17:]
    cipher     = AES.new(key, AES.MODE_CBC, iv)
    raw        = cipher.decrypt(ciphertext)

    seq_num, response_to, code, data_len = struct.unpack(">IIHH", raw[:12])
    return seq_num, response_to, code, raw[12 : 12 + data_len]


def _encode_dps(dps: dict) -> bytes:
    """Encode {dp_id: value} → Tuya BLE DP stream (3-byte header per DP)."""
    out = bytearray()
    for dp_id, value in dps.items():
        dp_id = int(dp_id)
        if isinstance(value, bool):
            out += struct.pack(">BBB", dp_id, _DPT_BOOL, 1)
            out += struct.pack("B", int(value))
        elif isinstance(value, int):
            out += struct.pack(">BBB", dp_id, _DPT_INT, 4)
            out += struct.pack(">i", value)
        elif isinstance(value, str):
            enc = value.encode("utf-8")
            out += struct.pack(">BBB", dp_id, _DPT_STR, len(enc))
            out += enc
        elif isinstance(value, (bytes, bytearray)):
            out += struct.pack(">BBB", dp_id, _DPT_RAW, len(value))
            out += bytes(value)
    return bytes(out)


def _decode_dps(data: bytes) -> dict[str, Any]:
    """Decode Tuya BLE DP stream → {dp_id_str: value}."""
    result = {}
    pos    = 0
    while pos + 3 <= len(data):
        dp_id   = data[pos]
        dp_type = data[pos + 1]
        dp_len  = data[pos + 2]
        pos    += 3
        if pos + dp_len > len(data):
            break
        raw = data[pos : pos + dp_len]
        pos += dp_len

        if dp_type == _DPT_BOOL:
            result[str(dp_id)] = bool(raw[0])
        elif dp_type == _DPT_INT:
            result[str(dp_id)] = struct.unpack(">i", raw)[0] if len(raw) == 4 else int.from_bytes(raw, "big", signed=True)
        elif dp_type == _DPT_ENUM:
            result[str(dp_id)] = raw[0]
        elif dp_type == _DPT_BITMAP:
            result[str(dp_id)] = int.from_bytes(raw, "big")
        elif dp_type in (_DPT_STR, _DPT_RAW):
            try:
                result[str(dp_id)] = raw.decode("utf-8")
            except UnicodeDecodeError:
                result[str(dp_id)] = raw.hex()
    return result


# ── Reassembler ───────────────────────────────────────────────────────────────

class _Reassembler:
    """Accumulates MTU-sized BLE notification chunks into complete packets."""

    def __init__(self, callback):
        self._buf      = bytearray()
        self._expected_len = 0
        self._expected_pkt = 0
        self._callback = callback

    def feed(self, data: bytes):
        pos = 0
        pkt_num, pos = _unpack_varint(data, pos)

        if pkt_num != self._expected_pkt:
            self._buf          = bytearray()
            self._expected_len = 0
            self._expected_pkt = 0
            if pkt_num != 0:
                return  # discard out-of-order

        if pkt_num == 0:
            self._buf = bytearray()
            self._expected_len, pos = _unpack_varint(data, pos)
            pos += 1  # skip protocol_version nibble

        self._buf += data[pos:]
        self._expected_pkt += 1

        if len(self._buf) >= self._expected_len:
            complete = bytes(self._buf[: self._expected_len])
            self._buf          = bytearray()
            self._expected_len = 0
            self._expected_pkt = 0
            self._callback(complete)


# ── Main class ────────────────────────────────────────────────────────────────

class TuyaBLEProtocol:
    """
    BLE transport that matches the TuyaProtocol interface used by TuyaDevice.

    Authentication sequence (executed on every connect):
      1. Send DEVICE_INFO (encrypted with login_key = MD5(local_key[:6]))
      2. Receive DEVICE_INFO response → extract srand, derive session_key
      3. Send PAIR (encrypted with session_key) with uuid+local_key[:6]+device_id
      4. Receive PAIR response (result 0=success, 2=already_paired)
      5. Normal operation: DEVICE_STATUS / DPS commands

    The device may send TIME1_REQ / TIME2_REQ at any time — we respond inline.
    """

    def __init__(
        self,
        mac_address: str,
        dev_id: str,
        local_key: str,
        device_uuid: str,
        protocol_version: float,
        listener,
    ):
        self.mac_address      = mac_address
        self.id               = dev_id
        self.local_key        = local_key
        self.device_uuid      = device_uuid
        self.protocol_version = protocol_version

        # Key derivation — Tuya's protocol uses only the first 6 chars of the local_key
        # as key material, giving ~36 bits of entropy. This is Tuya's design; a nearby
        # attacker with a BLE sniffer could brute-force the login_key offline.
        self._lk6        = local_key[:6].encode("utf-8")
        self._login_key  = md5(self._lk6).digest()
        self._session_key: bytes | None = None
        self._proto_ver  = 3  # updated from DEVICE_INFO response

        self._listener    = weakref.ref(listener)
        self._client: BleakClient | None = None
        self._seqno       = 1
        self._connected   = False
        self._reassembler = _Reassembler(self._on_packet)
        self._pending: dict[int, asyncio.Future] = {}
        self._heartbeat_task: asyncio.Task | None = None
        self._debug  = False
        self._name   = dev_id

        self.dps_to_request: dict = {}
        self.dispatched_dps: dict = {}

    # ── TuyaProtocol interface ────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected and self._client is not None and self._client.is_connected

    def enable_debug(self, enable: bool = False, friendly_name: str | None = None):
        self._debug = enable
        if friendly_name:
            self._name = friendly_name

    def add_dps_to_request(self, dp_indices):
        if isinstance(dp_indices, dict):
            self.dps_to_request.update(dp_indices)
        else:
            for dp in dp_indices:
                self.dps_to_request[str(dp)] = None

    def keep_alive(self, is_gateway: bool = False):
        pass  # heartbeat managed internally

    async def status(self, cid=None) -> dict:
        _, payload = await self._send(BLECmd.DEVICE_STATUS, b"")
        dps = _decode_dps(payload) if payload else {}
        self.dispatched_dps = dps
        return dps

    async def set_dps(self, dps: dict, cid=None):
        await self._send(BLECmd.DPS, _encode_dps(dps))
        self.dispatched_dps = dps

    async def update_dps(self, dps=None, cid=None):
        try:
            status = await self.status()
            if status and (listener := self._listener()):
                listener.status_updated(status)
        except Exception as exc:
            _LOGGER.debug("[%s] update_dps: %s", self._name, exc)

    async def reset(self, dpIds=None, cid=None):
        await self.update_dps()

    async def close(self):
        self._connected = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _do_connect(self):
        self._client = BleakClient(
            self.mac_address,
            disconnected_callback=self._on_disconnect,
        )
        await self._client.connect()
        await self._client.start_notify(TUYA_BLE_NOTIFY_UUID, self._on_notify)

        await self._auth()

        self._connected      = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        _LOGGER.debug("[%s] BLE connected and authenticated", self._name)

    def _on_disconnect(self, _client: BleakClient):
        _LOGGER.debug("[%s] BLE disconnected", self._name)
        self._connected = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(ConnectionError("BLE link lost"))
        self._pending.clear()
        if listener := self._listener():
            listener.disconnected("BLE connection lost")

    def _on_notify(self, _sender, data: bytearray):
        self._reassembler.feed(bytes(data))

    def _on_packet(self, raw_encrypted: bytes):
        """Called by _Reassembler when a complete encrypted blob is ready."""
        security_flag = raw_encrypted[0]
        key = self._get_key(security_flag)
        if key is None:
            _LOGGER.debug("[%s] BLE: no key for security_flag=0x%02x", self._name, security_flag)
            return

        try:
            seq, resp_to, code, payload = _parse_packet(raw_encrypted, key)
        except Exception as exc:
            _LOGGER.debug("[%s] BLE decrypt error: %s", self._name, exc)
            return

        if self._debug:
            _LOGGER.debug(
                "[%s] BLE ← seq=%d resp_to=%d code=0x%04x payload=%s",
                self._name, seq, resp_to, code, payload.hex() if payload else "(empty)",
            )

        # Time sync requests from device
        if code == BLECmd.TIME1_REQ:
            asyncio.create_task(self._send_time1(seq))
            return
        if code == BLECmd.TIME2_REQ:
            asyncio.create_task(self._send_time2(seq))
            return

        # Resolve a waiting send()
        if resp_to != 0 and resp_to in self._pending:
            fut = self._pending.pop(resp_to)
            if not fut.done():
                fut.set_result((code, payload))
            return

        # Unsolicited DP push
        if code in (BLECmd.DP_REPORT, BLECmd.DP_REPORT_T, BLECmd.DP_REPORT_S, BLECmd.DP_REPORT_ST):
            dps = _decode_dps(payload)
            if dps:
                self.dispatched_dps = dps
                if listener := self._listener():
                    listener.status_updated(dps)
            # Acknowledge
            asyncio.create_task(self._send_response(code, b"", seq))

    def _get_key(self, security_flag: int) -> bytes | None:
        if security_flag == 0x04:
            return self._login_key
        if security_flag == 0x05:
            return self._session_key
        if security_flag == 0x01:
            return None  # auth_key (not used for control)
        return None

    async def _auth(self):
        """Full DEVICE_INFO → PAIR authentication sequence."""
        # DEVICE_INFO
        _, payload = await self._raw_send(
            BLECmd.DEVICE_INFO, b"", self._login_key,
            security_flag=0x04, timeout=15.0,
        )
        if len(payload) < 46:
            raise ConnectionError("DEVICE_INFO response too short")

        self._proto_ver = payload[2]
        srand           = payload[6:12]
        self._session_key = md5(self._lk6 + srand).digest()
        _LOGGER.debug(
            "[%s] BLE auth: proto=%d srand=%s session_key=%s",
            self._name, self._proto_ver, srand.hex(), self._session_key.hex(),
        )

        # PAIR
        pair_data = bytearray()
        pair_data += self.device_uuid.encode("utf-8")
        pair_data += self._lk6
        pair_data += self.id.encode("utf-8")
        while len(pair_data) < 44:
            pair_data += b"\x00"

        _, pair_payload = await self._raw_send(
            BLECmd.PAIR, bytes(pair_data), self._session_key,
            security_flag=0x05, timeout=15.0,
        )
        result = pair_payload[0] if pair_payload else 255
        if result not in (0, 2):
            raise ConnectionError(f"PAIR failed: result={result}")
        _LOGGER.debug("[%s] BLE auth: PAIR result=%d (paired)", self._name, result)

    async def _raw_send(
        self,
        code: int,
        payload: bytes,
        key: bytes,
        security_flag: int = 0x05,
        response_to: int = 0,
        timeout: float = TIMEOUT_CMD,
    ) -> tuple[int, bytes]:
        """Low-level send: encrypts, chunks, writes, awaits response."""
        seq  = self._seqno
        self._seqno += 1

        loop = asyncio.get_running_loop()
        fut  = loop.create_future()
        self._pending[seq] = fut

        packets = _build_packets(
            seq, code, payload, key,
            response_to=response_to,
            security_flag=security_flag,
            protocol_version=self._proto_ver,
        )

        if self._debug:
            _LOGGER.debug(
                "[%s] BLE → seq=%d code=0x%04x payload=%s",
                self._name, seq, code, payload.hex() if payload else "(empty)",
            )

        for pkt in packets:
            await self._client.write_gatt_char(TUYA_BLE_WRITE_UUID, pkt, response=True)

        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            raise

    async def _send(self, code: int, payload: bytes, timeout: float = TIMEOUT_CMD) -> tuple[int, bytes]:
        """Authenticated send using session_key."""
        if not self.is_connected or self._session_key is None:
            raise ConnectionError("BLE not connected / not authenticated")
        return await self._raw_send(code, payload, self._session_key, timeout=timeout)

    async def _send_response(self, code: int, payload: bytes, response_to: int):
        """Send a response to a device-initiated message (e.g. time request)."""
        if not self._client or not self._client.is_connected or self._session_key is None:
            return
        seq  = self._seqno
        self._seqno += 1
        packets = _build_packets(
            seq, code, payload, self._session_key,
            response_to=response_to,
            security_flag=0x05,
            protocol_version=self._proto_ver,
        )
        for pkt in packets:
            try:
                await self._client.write_gatt_char(TUYA_BLE_WRITE_UUID, pkt, response=False)
            except Exception:
                pass

    async def _send_time1(self, device_seq: int):
        ts_ms = int(time.time() * 1000)
        tz    = -int(__import__("time").timezone // 36)
        await self._send_response(
            BLECmd.TIME1_REQ,
            str(ts_ms).encode() + struct.pack(">h", tz),
            device_seq,
        )

    async def _send_time2(self, device_seq: int):
        t  = __import__("time").localtime()
        tz = -int(__import__("time").timezone // 36)
        data = struct.pack(
            ">BBBBBBBh",
            t.tm_year % 100, t.tm_mon, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec,
            t.tm_wday, tz,
        )
        await self._send_response(BLECmd.TIME2_REQ, data, device_seq)

    async def _heartbeat_loop(self):
        while self._connected:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self._send(BLECmd.DEVICE_STATUS, b"", timeout=8.0)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.debug("[%s] heartbeat: %s", self._name, exc)


# ── Factory ───────────────────────────────────────────────────────────────────

async def connect_ble(
    mac_address: str,
    device_id: str,
    device_uuid: str,
    local_key: str,
    protocol_version: float,
    enable_debug: bool,
    listener,
) -> TuyaBLEProtocol:
    """Connect to a Tuya BLE device and return a ready, authenticated TuyaBLEProtocol."""
    proto = TuyaBLEProtocol(
        mac_address=mac_address,
        dev_id=device_id,
        local_key=local_key,
        device_uuid=device_uuid,
        protocol_version=protocol_version,
        listener=listener,
    )
    proto.enable_debug(enable_debug)
    await proto._do_connect()
    return proto
