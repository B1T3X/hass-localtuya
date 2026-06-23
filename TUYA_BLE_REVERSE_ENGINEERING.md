# Reverse Engineering the Tuya BLE Smart Plug Protocol

## Background

A Tuya smart plug had its WiFi broken but BLE (Bluetooth Low Energy) still functional. The goal was to control it from Home Assistant without cloud access. An existing custom integration (localtuya) had a BLE module, but it used the wrong protocol entirely. This document walks through how we discovered that, identified the correct protocol, and achieved full local BLE control.

---

## Phase 1: Understanding BLE at the Wire Level

Before writing any code, you need to know *how BLE actually works* for IoT devices.

**BLE uses a GATT (Generic Attribute Profile) architecture.** A device exposes a tree of *services*, each containing *characteristics*. Characteristics are the actual data endpoints — you read from them, write to them, or subscribe to notifications. Under the hood each characteristic lives at a numbered *handle* in the attribute table, and the protocol that moves data between client and server is ATT (Attribute Protocol).

For a Tuya plug, the relevant GATT structure is:

```
Service:         00001910-0000-1000-8000-00805f9b34fb
  Write char:    00002b11-0000-1000-8000-00805f9b34fb   (client → device)
  Notify char:   00002b10-0000-1000-8000-00805f9b34fb   (device → client)
```

To receive notifications, the client must *enable* them by writing `0x01 0x00` to the CCCD (Client Characteristic Configuration Descriptor) — a small descriptor that lives at the handle immediately after the characteristic itself. This is a one-time setup step using `start_notify()` in bleak; without it the device will never send anything back regardless of what you write.

**MTU constraint.** BLE has a default Maximum Transmission Unit of 23 bytes per ATT packet (20 bytes usable after the 3-byte ATT header). Longer messages must be fragmented into multiple writes. The Tuya BLE protocol uses a custom framing scheme (varint-based, described later) to handle this fragmentation.

---

## Phase 2: The First Attempt — and Why It Silently Failed

The existing `ble.py` in localtuya was using the **Tuya WiFi "55aa" protocol** framing, with AES-ECB encryption and an MD5 of the full 16-byte local_key. Writes were going out to the device but zero notifications came back.

The naive interpretation: maybe CCCD wasn't enabled, or the MTU negotiation was wrong. We added an explicit write to the Client Supported Features characteristic (handle 0x2b29) and added longer waits. Still nothing.

**The right tool here was `btmon`.** This is a Linux utility that reads raw HCI (Host Controller Interface) events from the Bluetooth kernel driver — *before* any userspace protocol parsing. It gives you the ground truth of what's actually happening at the BLE layer.

```bash
sudo btmon -w /tmp/btmon2.log &
python3 /tmp/ble_test2.py
```

The btmon capture revealed three things:

1. **CCCD was correctly enabled.** The log showed an ATT Write to handle `0x0015` containing `01 00` — notifications were subscribed.
2. **Writes were being delivered.** For each `write_gatt_char()` call, the log showed an ATT Write Response from the device — meaning it received and acknowledged the data.
3. **Zero GATT notifications returned.** The device's L2CAP Connection Parameter Update confirmed it was alive (it wanted to negotiate connection intervals), but it never initiated any notification.

The conclusion was unambiguous: **the device receives the writes but chooses not to respond.** This isn't a BLE transport issue — the device is rejecting the content. It requires a valid *authentication handshake* before it will reply to anything.

---

## Phase 3: Finding the Correct Protocol

The obvious next step: look at what open-source Tuya BLE integrations actually do.

A search for "ha_tuya_ble" turned up the GitHub repository `PlusPlus-ua/ha_tuya_ble`. Crucially, reading its source rather than just its README revealed that it uses a completely *different* protocol from the WiFi stack:

| Property | WiFi "55aa" protocol | BLE protocol (ha_tuya_ble) |
|---|---|---|
| Framing | Fixed `55 AA` header + length | Varint-chunked GATT packets |
| Encryption | AES-128 ECB | AES-128 CBC (per-packet random IV) |
| Key derivation | `MD5(full 16-char local_key)` | `MD5(first 6 chars of local_key)` |
| Auth | None (local key is enough) | Two-step: DEVICE_INFO → PAIR |
| DP header | 4 bytes `(BBH)` | 3 bytes `(BBB)` |

This is why the original code produced zero responses — it was sending WiFi protocol frames over BLE. The device simply didn't recognise them.

---

## Phase 4: Reconstructing the Protocol from Source

Here's each layer of the protocol, from the bottom up.

### Layer 1: AES-128 CBC Encryption

Every message is encrypted. The key depends on the *phase* of the connection:

- During `DEVICE_INFO`: use `login_key = MD5(local_key[:6])`
- After auth: use `session_key = MD5(local_key[:6] + srand)` where `srand` is 6 bytes from the device's `DEVICE_INFO` response

CBC mode requires a fresh random IV per message — this is critical for security (ECB reuses structure; CBC with a random IV does not). The IV is prepended to the ciphertext:

```
encrypted_blob = security_flag(1B) + IV(16B) + AES_CBC(key, IV, raw_message)
```

The `security_flag` byte tells the receiver which key to use:
- `0x04` = login_key
- `0x05` = session_key

### Layer 2: Raw Message Format

Before encryption, each message is structured as:

```
seq_num(4B, big-endian uint32)
response_to(4B, big-endian uint32)   ← seq of the message we're responding to, else 0
command_code(2B, big-endian uint16)
payload_length(2B, big-endian uint16)
payload(N bytes)
CRC-16 MODBUS(2B)
zero-padding to next 16-byte boundary
```

The CRC-16 MODBUS polynomial is `0xA001`, initial value `0xFFFF`. It covers everything from `seq_num` through `payload`.

```python
def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            tmp = crc & 1
            crc >>= 1
            if tmp:
                crc ^= 0xA001
    return crc
```

### Layer 3: BLE MTU Fragmentation (Varint Framing)

The encrypted blob is split into 20-byte chunks. Each chunk is prefixed with a LEB128 (varint) encoded packet number:

- **First chunk**: `varint(0) + varint(total_encrypted_length) + byte(protocol_version << 4) + data`
- **Subsequent chunks**: `varint(N) + data`

LEB128 encodes integers 7 bits at a time; the MSB of each byte is set if more bytes follow:

```python
def pack_varint(value: int) -> bytes:
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
```

The receiver accumulates chunks until it has `total_encrypted_length` bytes, then decrypts the whole blob.

### Layer 4: Command Codes

The `command_code` field determines message type:

| Code | Direction | Meaning |
|------|-----------|---------|
| `0x0000` | bidirectional | DEVICE_INFO (auth step 1) |
| `0x0001` | bidirectional | PAIR (auth step 2) |
| `0x0002` | client → device | DPS (send datapoint values) |
| `0x0003` | client → device | DEVICE_STATUS (request current state) |
| `0x8001` | device → client | DP_REPORT (unsolicited state push) |
| `0x8011` | device → client | TIME1_REQ (device asking for Unix timestamp) |
| `0x8012` | device → client | TIME2_REQ (device asking for struct time) |

### Layer 5: Datapoint Encoding

DPs (datapoints) are the actual device state — switch on/off, power reading, etc. Each DP has a numeric ID, a type, and a value. In BLE the encoding uses a **3-byte header** per DP:

```
dp_id(1B) + dp_type(1B) + value_length(1B) + value(N bytes)
```

> **Note:** The WiFi protocol uses a 4-byte header `(dp_id: 1B)(dp_type: 1B)(dp_len: 2B)`. This 1-byte difference makes decode_dps return empty results if you copy the WiFi implementation.

Types:

| Value | Name | Encoding |
|-------|------|----------|
| `0` | RAW | raw bytes |
| `1` | BOOL | 1 byte, `0x00` or `0x01` |
| `2` | INT | 4 bytes, signed big-endian int32 |
| `3` | STRING | UTF-8 bytes |
| `4` | ENUM | 1 byte |
| `5` | BITMAP | 4 bytes, unsigned big-endian int32 |

---

## Phase 5: The UUID Problem

The PAIR command's payload must be exactly **44 bytes**:

```
device_uuid(16B) + local_key[:6](6B) + device_id(22B)
```

The device UUID is *not* the same as the device ID. The device ID (`bfb9da7...`) is the Tuya cloud identifier. The UUID is a separate per-hardware identifier burned in at manufacturing.

Our first PAIR attempt used the device_id as the UUID, making the payload `22 + 6 + 22 = 50` bytes. The device silently rejected it and disconnected, with no error code.

The UUID lives in the Tuya IoT Platform. We retrieved it by querying the Tuya OpenAPI with the cloud credentials localtuya already stores in Home Assistant's config:

```python
# Step 1: POST /v1.0/token?grant_type=1  → access_token
# Step 2: GET  /v1.0/devices/{device_id} → result.uuid
```

The request signing scheme is HMAC-SHA256 over:

```
client_id + access_token + timestamp_ms + nonce + "GET\n{sha256('')}\n\n{path}"
```

The UUID returned was `54fc4542fcd8e73c` — 16 characters, giving exactly 44 bytes.

---

## Phase 6: The Authentication Flow in Detail

### DEVICE_INFO

Send an empty payload, encrypted with `login_key`, `security_flag=0x04`, `code=0x0000`:

```python
login_key = hashlib.md5(local_key[:6].encode()).digest()
packets = build_packets(seq=1, code=0x0000, payload=b"", key=login_key, sec_flag=0x04)
```

The device responds with a 46+ byte payload:
- `dat[2]` — protocol version (e.g. `3` for protocol 3.3/3.4)
- `dat[6:12]` — `srand`, 6 random bytes used as a nonce

```python
protocol_version = response[2]
srand = response[6:12]
session_key = hashlib.md5(local_key[:6].encode() + srand).digest()
```

### PAIR

Build the 44-byte payload and send it encrypted with `session_key`:

```python
pair_data = device_uuid.encode() + local_key[:6].encode() + device_id.encode()
# pad to exactly 44 bytes if shorter
while len(pair_data) < 44:
    pair_data += b"\x00"

packets = build_packets(seq=2, code=0x0001, payload=pair_data, key=session_key, sec_flag=0x05)
```

The response's first byte is the result code:
- `0` = newly paired
- `2` = already paired (normal on subsequent connects)

**Interleaved TIME1_REQ.** Between PAIR send and PAIR response, the device may send a `TIME1_REQ` (code `0x8011`). This must be handled inline — your event loop must route any incoming message, not just wait for code `0x0001`. The TIME1 response payload is:

```python
# timestamp as ASCII milliseconds (NOT a binary integer)
ts_ms_ascii = str(int(time.time() * 1000)).encode()
timezone_offset = struct.pack(">h", -int(time.timezone // 36))  # quarter-hours from UTC
response_payload = ts_ms_ascii + timezone_offset
```

### Normal Operation

All subsequent messages use `session_key` and `sec_flag=0x05`.

```python
# Request current state
build_packets(seq=N, code=0x0003, payload=b"", key=session_key)

# Turn switch on (DP 1 = True)
dp_payload = struct.pack(">BBB", 1, 1, 1) + struct.pack("B", 1)
build_packets(seq=N, code=0x0002, payload=dp_payload, key=session_key)

# Device pushes state changes unsolicited via DP_REPORT (code=0x8001)
# You must ACK these: send code=0x8001, empty payload, response_to=device_seq
```

---

## Phase 7: Test Iteration Summary

Each script confirmed one more layer of the stack:

| Script | What worked | What was wrong |
|--------|------------|----------------|
| `ble_test2.py` | CCCD enabled, writes ACKed (btmon confirmed) | Wrong protocol — WiFi 55aa frames |
| `ble_test3.py` | DEVICE_INFO succeeded, got srand | PAIR timeout — payload was 50 bytes (used device_id as UUID) |
| `ble_test5.py` | Correct session key derivation | Still wrong UUID (used advertisement bytes) |
| `ble_test6.py` | PAIR result=2 — authenticated! | `decode_dps` returned `{}` (4-byte header bug) |
| `ble_test7.py` | Full auth flow + TIME1 handling | `decode_dps` still broken |
| `ble_test8.py` | Switch toggled OFF then ON — confirmed working | — |

The `decode_dps` bug persisted through several scripts: it used `struct.unpack(">H", data[pos+2:pos+4])` (2-byte length) for the DP length field. In BLE the length is 1 byte at `data[pos+2]`. This caused the parser to read a nonsensically large length, skip past the entire payload, and return `{}` every time.

---

## Key Lessons

**1. btmon before assumptions.**
When BLE seems to not be working, capture at the HCI layer first. It tells you definitively whether the issue is transport (CCCD, MTU, ATT errors) or application (device ignores valid data). In this case, everything at the BLE layer was working perfectly — the device was rejecting the *content*.

**2. Read the reference implementation, not just the docs.**
Tuya has multiple incompatible protocol versions across WiFi/BLE and firmware generations. The ha_tuya_ble source code was the authoritative reference — no amount of reading Tuya's public documentation would have revealed the specific varint framing or the 3-byte DP header.

**3. Key derivation is easy to get wrong silently.**
`MD5(full 16-byte key)` vs `MD5(first 6 chars)` produces completely different keys. There's no error message — you just get garbage ciphertext and the device ignores it. If DEVICE_INFO gets no response, key derivation is the first thing to check.

**4. Protocol version matters for the framing nibble.**
The first chunk of every message contains `protocol_version << 4` as a byte. If you hardcode `2` but the device is protocol 3.3, you must use `3`. Extract it from the DEVICE_INFO response (`dat[2]`) rather than hardcoding.

**5. Payload size requirements are silent hard errors.**
The 44-byte PAIR constraint isn't documented anywhere publicly visible. The device just disconnects on a wrong-size payload. Figuring out the correct size required reading the ha_tuya_ble source that constructs the same payload.

**6. Async event loop interleaving matters.**
The device sends `TIME1_REQ` *between* receiving PAIR and sending the PAIR response. If your event loop only waits for `code == 0x0001`, it will block indefinitely while the time request sits unhandled. The correct pattern is a general event loop that dispatches any incoming code.

---

## Complete Protocol Reference

```
Key derivation
──────────────
lk6        = local_key[:6].encode('utf-8')
login_key  = MD5(lk6)                              # used for DEVICE_INFO
session_key = MD5(lk6 + srand)                     # derived after DEVICE_INFO


Packet construction
───────────────────
raw = seq(4be) + resp_to(4be) + code(2be) + len(payload)(2be) + payload + CRC16(2be)
raw = zero_pad(raw, multiple_of=16)
enc = security_flag(1B) + IV(16B) + AES_CBC(key, IV, raw)

chunks:
  chunk[0] = varint(0) + varint(len(enc)) + byte(proto_ver << 4) + enc[:fill]
  chunk[n] = varint(n) + enc[next:fill]
  each chunk ≤ 20 bytes total


Authentication sequence
───────────────────────
→ code=0x0000  payload=b""   key=login_key   sec_flag=0x04   (DEVICE_INFO)
← code=0x0000  dat[2]=proto_ver, dat[6:12]=srand  →  derive session_key

→ code=0x0001  payload=uuid(16)+lk6(6)+dev_id(22) padded to 44B
               key=session_key  sec_flag=0x05   (PAIR)
← code=0x8011? respond: ASCII(ts_ms) + int16be(tz_offset)   (TIME1 if device asks)
← code=0x0001  dat[0]=0 (new) or 2 (already paired)


Control
───────
→ code=0x0003  payload=b""          (DEVICE_STATUS — request current DPs)
→ code=0x0002  payload=encode_dps(…) (DPS — set DP values)
← code=0x8001  payload=decode_dps(…) (DP_REPORT — unsolicited push from device)
   must ACK: → code=0x8001  payload=b""  response_to=device_seq


DP wire format (3-byte header)
──────────────────────────────
dp_id(1B) + dp_type(1B) + value_len(1B) + value(N bytes)

types:  0=raw  1=bool(1B)  2=int32be(4B)  3=str  4=enum(1B)  5=bitmap(4B)
```
