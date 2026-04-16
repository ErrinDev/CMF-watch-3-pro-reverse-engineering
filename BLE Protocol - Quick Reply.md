(full disclosure, this summary has been made by claude, as I am slightly out of my depth here.)

## Environment

- App: Nothing X (`com.nothing.smartcenter`)
- Capture method: Android HCI snoop log → Wireshark
- ATT Handle: `0x3852`
- ATT Opcode: `0x52` (Write Without Response)

---

## Packet Structure

Full HCI ACL packet layout for a quick reply write:

```
[02 00 02]          HCI ACL header
[XX 00]             Total length
[YY 00]             L2CAP length
[04 00]             L2CAP channel ID (ATT)
[52 38]             ATT opcode 0x52 = Write Without Response, handle 0x3852
[00]                Reserved
[f5 00]             Application-level command ID
[ZZ ff ff 00]       ZZ = encrypted payload length in hex (e.g. 0x20 = 32 bytes)
[01 00 01]          Command subtype + context (possibly slot/list identifier)
[90 73]             Fixed 2-byte prefix — device identifier or protocol version
[16 bytes]          IV (random per session, but reused within same session)
[N bytes]           AES-CBC encrypted payload (N is always a multiple of 16)
```

---

## Encryption

- **Cipher: AES-CBC** with PKCS#7 padding
- **IV: 16 bytes**, located immediately after the `90 73` prefix
- The IV is random per connection session but **reused across multiple writes in the same session** — this is a known weakness of CBC mode; identical plaintext blocks produce identical ciphertext blocks, allowing fingerprinting of unchanged content without decryption
- **Key: unknown** — not transmitted in the packet; likely derived during BLE pairing/bonding or negotiated via a separate GATT characteristic read

---

## Payload Size Observations (Quick Replies)

The entire quick reply list is serialised into a single plaintext blob and encrypted together. Writing to any slot sends the full list.

|Entries (all single "a")|Encrypted bytes|
|---|---|
|0 (empty list)|16|
|1|16|
|2|16|
|3|16|
|7|16|
|8|32|
|10|48|

The payload jumps by 16 bytes (one AES block) every ~7-8 single-character entries, consistent with AES-CBC block boundaries and PKCS#7 padding.

### Variable-length entry test

With 10 entries where one entry was extended to 10 "a"s:

|State|Encrypted bytes|
|---|---|
|10 × single "a"|48|
|9 × single "a" + 1 × ten "a"s|64|

Payload grew by exactly 16 bytes when adding 9 characters to one entry — confirms AES block boundary behaviour.

### Inferred serialisation format

Each entry is variable length. Likely format (to be confirmed via Frida):

```
[count] [len] [text] [len] [text] [len] [text] ...
```

or null-terminated:

```
[count] text_1 0x00 text_2 0x00 ...
```

Approximately 2 bytes overhead per single-character entry based on 7 entries fitting in ≤15 bytes of plaintext.

---

## Key Observations & Weaknesses

1. **IV reuse within session** — AES-CBC with a reused IV leaks information about identical plaintext blocks. Unchanged entries between two writes will produce identical ciphertext blocks at the same offset.
    
2. **Length field is plaintext** — The `ZZ` byte in `[ZZ ff ff 00]` is the encrypted payload length in decimal, transmitted unencrypted. Payload size leaks approximate content length even without decryption.
    
3. **Write Without Response** — The watch sends no ATT-level acknowledgement. There is no challenge/response visible at the ATT layer for these writes.
    
4. **Fixed `90 73` prefix** — Appears in every observed packet. Likely a protocol version or device class identifier.
    

---

## Outstanding Questions

- Where is the session key stored / how is it derived?
- Is there a GATT characteristic read prior to writes that contains the IV or a nonce?
- Does the watch perform any integrity check (e.g. HMAC) on the decrypted payload, or does it trust any well-padded plaintext?
- What is the full GATT service/characteristic UUID for handle `0x3852`?
- Are firmware OTA writes sent to the same characteristic or a different one?

---

## Next Steps

- [ ] Capture full GATT service enumeration to map all characteristic UUIDs
- [ ] Identify the characteristic read(s) that precede writes — likely key/nonce negotiation
- [ ] Use Frida to hook the Nothing X app and intercept plaintext before encryption
- [ ] Capture OTA firmware update flow and compare packet structure
- [ ] Cross-reference with Gadgetbridge CMF implementation for known protocol details
