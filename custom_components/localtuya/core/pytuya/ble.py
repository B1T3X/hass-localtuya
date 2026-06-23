"""Tuya BLE transport — local control over Bluetooth."""

from __future__ import annotations

import asyncio
import logging
import struct
import weakref
from hashlib import md5

from bleak import BleakClient
from bleak.exc import BleakError

from .cipher import AESCipher

_LOGGER = logging.getLogger(__name__)

# ── GATT UUIDs ────────────────────────────────────────────────────────────────
TUYA_BLE_SERVICE_UUID = "0000fd50-0000-1000-8000-00805f9b34fb"
TUYA_BLE_WRITE_UUID   = "00000001-0000-1000-8000-00805f9b34fb"
TUYA_BLE_NOTIFY_UUID  = "00000002-0000-1000-8000-00805f9b34fb"

# ── BLE commands ──────────────────────────────────────────────────────────────
class BLECmd:
    DEVICE_INFO        = 0x00
    PAIR               = 0x01
    ACTIVE             = 0x02
    SESS_KEY_NEG_START = 0x03
    SESS_KEY_NEG_RES   = 0x04
    SESS_KEY_NEG_FINISH= 0x05
    HEARTBEAT          = 0x06
    DP_QUERY           = 0x0e
    DP_SEND            = 0x1b
    DP_REPORT          = 0x22
    DP_REPORT_V2       = 0x25

# ── DP types ──────────────────────────────────────────────────────────────────
_DP_BOOL   = 0x01
_DP_ENUM   = 0x02
_DP_INT    = 0x03
_DP_STR    = 0x04
_DP_BITMAP = 0x05
_DP_RAW    = 0x06

# ── Packet constants ──────────────────────────────────────────────────────────
_HEAD = b'\x55\xaa'
_TAIL = b'\xaa\x55'
# Packet layout (after _HEAD):
#   version:1  seq:4  cmd:1  data_len:2  → 8 bytes
_HDR_FMT = '>BIBH'   # big-endian: uchar, uint32, uchar, uint16
_HDR_LEN = struct.calcsize(_HDR_FMT)   # == 8
_OVERHEAD = len(_HEAD) + _HDR_LEN + 1 + len(_TAIL)  # 13 bytes total overhead
_BLE_MTU  = 20  # conservative; renegotiated after connect

TIMEOUT_CMD       = 10.0   # seconds to wait for a command response
HEARTBEAT_INTERVAL = 10.0  # seconds between heartbeats


# ── Helpers ───────────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    """Simple sum-mod-256 checksum used by Tuya BLE."""
    return sum(data) & 0xFF


def _pack(version: int, seq: int, cmd: int, payload: bytes) -> bytes:
    """Assemble a Tuya BLE packet (payload must already be encrypted)."""
    hdr = _HEAD + struct.pack(_HDR_FMT, version, seq, cmd, len(payload))
    body = hdr + payload
    return body + struct.pack('B', _checksum(body)) + _TAIL


def _unpack(raw: bytes):
    """Parse a complete Tuya BLE packet.

    Returns (version, seq, cmd, payload) or raises ValueError.
    """
    if len(raw) < _OVERHEAD:
        raise ValueError("packet too short")
    if raw[:2] != _HEAD or raw[-2:] != _TAIL:
        raise ValueError(f"bad framing: {raw[:2].hex()} / {raw[-2:].hex()}")

    version, seq, cmd, data_len = struct.unpack(_HDR_FMT, raw[2:2 + _HDR_LEN])

    expected_len = _OVERHEAD + data_len
    if len(raw) < expected_len:
        raise ValueError("truncated packet")

    payload  = raw[2 + _HDR_LEN : 2 + _HDR_LEN + data_len]
    crc_byte = raw[2 + _HDR_LEN + data_len]
    body     = raw[:2 + _HDR_LEN + data_len]

    if crc_byte != _checksum(body):
        _LOGGER.debug("BLE checksum mismatch (got %02x, expected %02x)", crc_byte, _checksum(body))

    return version, seq, cmd, payload


def _encode_dps(dps: dict) -> bytes:
    """Encode {dp_id: value} → Tuya BLE binary DP stream."""
    out = bytearray()
    for dp_id, value in dps.items():
        dp_id = int(dp_id)
        if isinstance(value, bool):
            out += struct.pack('>BBH', dp_id, _DP_BOOL, 1) + struct.pack('B', int(value))
        elif isinstance(value, int):
            out += struct.pack('>BBH', dp_id, _DP_INT, 4) + struct.pack('>i', value)
        elif isinstance(value, str):
            enc = value.encode('utf-8')
            out += struct.pack('>BBH', dp_id, _DP_STR, len(enc)) + enc
        elif isinstance(value, (bytes, bytearray)):
            out += struct.pack('>BBH', dp_id, _DP_RAW, len(value)) + bytes(value)
    return bytes(out)


def _decode_dps(data: bytes) -> dict:
    """Decode Tuya BLE binary DP stream → {dp_id_str: value}."""
    result = {}
    i = 0
    while i + 4 <= len(data):
        dp_id, dp_type, dp_len = struct.unpack('>BBH', data[i:i + 4])
        i += 4
        if i + dp_len > len(data):
            break
        raw = data[i:i + dp_len]
        i += dp_len
        if dp_type == _DP_BOOL:
            result[str(dp_id)] = bool(raw[0])
        elif dp_type in (_DP_ENUM, ):
            result[str(dp_id)] = raw[0]
        elif dp_type == _DP_INT:
            result[str(dp_id)] = struct.unpack('>i', raw)[0]
        elif dp_type == _DP_BITMAP:
            result[str(dp_id)] = struct.unpack('>I', raw)[0]
        elif dp_type in (_DP_STR, _DP_RAW):
            try:
                result[str(dp_id)] = raw.decode('utf-8')
            except UnicodeDecodeError:
                result[str(dp_id)] = raw.hex()
    return result


# ── Main class ────────────────────────────────────────────────────────────────

class TuyaBLEProtocol:
    """BLE transport that matches the TuyaProtocol interface used by TuyaDevice."""

    def __init__(
        self,
        mac_address: str,
        dev_id: str,
        local_key: str,
        protocol_version: float,
        listener,
    ):
        self.mac_address   = mac_address
        self.id            = dev_id
        self.local_key     = local_key
        self.protocol_version = protocol_version

        # BLE key = MD5(local_key) — different from the raw local_key used over TCP
        ble_key = md5(local_key.encode('utf-8')).digest()
        self._cipher = AESCipher(ble_key)

        self._listener     = weakref.ref(listener)
        self._client: BleakClient | None = None
        self._seqno        = 1
        self._connected    = False
        self._recv_buf     = bytearray()
        self._pending: dict[int, asyncio.Future] = {}
        self._heartbeat_task: asyncio.Task | None = None
        self._debug        = False
        self._name         = dev_id
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
        """No-op — heartbeat is managed internally."""

    async def status(self, cid=None) -> dict:
        """Query all DPs and return status dict."""
        _, payload = await self._send(BLECmd.DP_QUERY, b'')
        dps = _decode_dps(payload)
        self.dispatched_dps = dps
        return dps

    async def set_dps(self, dps: dict, cid=None):
        """Write DP values to device."""
        await self._send(BLECmd.DP_SEND, _encode_dps(dps))
        self.dispatched_dps = dps

    async def update_dps(self, dps=None, cid=None):
        """Request a status refresh."""
        try:
            status = await self.status()
            if status and (listener := self._listener()):
                listener.status_updated(status)
        except Exception as exc:
            _LOGGER.debug("[%s] update_dps: %s", self._name, exc)

    async def reset(self, dpIds=None, cid=None):
        """Reset — BLE has no reset concept; just refresh status."""
        await self.update_dps()

    async def close(self):
        """Disconnect from the BLE device."""
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
        """Open BLE connection and start notify handler + heartbeat."""
        self._client = BleakClient(
            self.mac_address,
            disconnected_callback=self._on_disconnect,
        )
        await self._client.connect()
        # Negotiate a larger MTU if possible (bleak handles this per-platform)
        try:
            mtu = self._client.mtu_size
            _LOGGER.debug("[%s] BLE MTU = %d", self._name, mtu)
        except AttributeError:
            pass
        await self._client.start_notify(TUYA_BLE_NOTIFY_UUID, self._on_notify)
        self._connected = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        _LOGGER.debug("[%s] BLE connected to %s", self._name, self.mac_address)

    def _on_disconnect(self, _client: BleakClient):
        """Bleak disconnect callback — fires on unexpected drops."""
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
        """Accumulate incoming notification chunks and parse complete packets."""
        self._recv_buf.extend(data)
        self._drain_buffer()

    def _drain_buffer(self):
        """Extract and handle every complete packet in _recv_buf."""
        buf = self._recv_buf
        while True:
            # Scan for header
            idx = bytes(buf).find(_HEAD)
            if idx < 0:
                buf.clear()
                return
            if idx:
                del buf[:idx]

            # Need at least the fixed header to know payload length
            if len(buf) < 2 + _HDR_LEN:
                return

            _, _, _, data_len = struct.unpack(_HDR_FMT, buf[2:2 + _HDR_LEN])
            total = _OVERHEAD + data_len
            if len(buf) < total:
                return  # wait for more chunks

            raw = bytes(buf[:total])
            del buf[:total]
            self._dispatch(raw)

    def _dispatch(self, raw: bytes):
        """Handle one complete raw packet."""
        try:
            version, seq, cmd, payload = _unpack(raw)
        except ValueError as exc:
            _LOGGER.debug("[%s] bad packet: %s", self._name, exc)
            return

        # Decrypt
        if payload:
            try:
                payload = self._cipher.decrypt(payload, use_base64=False, decode_text=False)
            except Exception as exc:
                _LOGGER.debug("[%s] decrypt failed: %s", self._name, exc)
                return

        if self._debug:
            _LOGGER.debug("[%s] BLE ← cmd=0x%02x seq=%d payload=%s", self._name, cmd, seq, payload.hex() if payload else '')

        # Resolve a waiting send() call
        if seq in self._pending:
            fut = self._pending.pop(seq)
            if not fut.done():
                fut.set_result((cmd, payload))
            return

        # Unsolicited push from device
        if cmd in (BLECmd.DP_REPORT, BLECmd.DP_REPORT_V2):
            dps = _decode_dps(payload)
            if dps:
                self.dispatched_dps = dps
                if listener := self._listener():
                    listener.status_updated(dps)

    async def _send(self, cmd: int, payload: bytes, timeout: float = TIMEOUT_CMD) -> tuple[int, bytes]:
        """Encrypt, frame, send a command and await the response."""
        if not self.is_connected:
            raise ConnectionError("BLE not connected")

        seq = self._seqno
        self._seqno += 1

        encrypted = self._cipher.encrypt(payload, use_base64=False, pad=True) if payload else b''
        packet    = _pack(int(self.protocol_version), seq, cmd, encrypted)

        loop = asyncio.get_running_loop()
        fut  = loop.create_future()
        self._pending[seq] = fut

        mtu = getattr(self._client, 'mtu_size', _BLE_MTU) or _BLE_MTU
        for i in range(0, len(packet), mtu):
            await self._client.write_gatt_char(TUYA_BLE_WRITE_UUID, packet[i:i + mtu], response=False)

        if self._debug:
            _LOGGER.debug("[%s] BLE → cmd=0x%02x seq=%d payload=%s", self._name, cmd, seq, payload.hex() if payload else '')

        try:
            async with asyncio.timeout(timeout):
                return await fut
        except TimeoutError:
            self._pending.pop(seq, None)
            raise

    async def _heartbeat_loop(self):
        while self._connected:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self._send(BLECmd.HEARTBEAT, b'', timeout=5.0)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.debug("[%s] heartbeat: %s", self._name, exc)


# ── Factory (mirrors pytuya.connect) ─────────────────────────────────────────

async def connect_ble(
    mac_address: str,
    device_id: str,
    local_key: str,
    protocol_version: float,
    enable_debug: bool,
    listener,
) -> TuyaBLEProtocol:
    """Connect to a Tuya BLE device and return a ready TuyaBLEProtocol."""
    proto = TuyaBLEProtocol(
        mac_address=mac_address,
        dev_id=device_id,
        local_key=local_key,
        protocol_version=protocol_version,
        listener=listener,
    )
    proto.enable_debug(enable_debug)
    await proto._do_connect()
    return proto
