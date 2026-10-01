## IEC 60870-5-104 parser for Zeek
**NOTE: This parser was created using IEC_104 PCAPs found online. It has not been tested in a full production environment!!! Please test with PCAP data from your production environment in a lab environment before adding this script in production.**

`iec_104.zeek` is a Zeek script that reads IEC 60870-5-104 (IEC-104) traffic on TCP/2404 and turns it into a structured, searchable `iec104.log`. It also raises Notices when someone writes to a protection setpoint, a quiet and high-impact
action that ordinary volume- or identity-based rules miss.

IEC-104 is the TCP/IP telecontrol protocol that connects SCADA masters (HMIs) to substation RTUs/IEDs. Out of the box, Zeek has no IEC-104 analyzer, so this traffic is just opaque bytes on port 2404. This package makes every frame, and every information object, a first-class, queryable record.

---

## What it does, in one paragraph

For each packet on TCP/2404, the script walks every IEC-104 APDU in the payload, classifies it as an I-, S-, or U-frame, and for I-frames, decodes the ASDU: its TypeID, Cause of Transmission, Common Address, and each information object's
IOA and value. Every object becomes one `iec104.log` row with both machine fields (numbers) and human-readable descriptions (names). On top of logging, it evaluates `C_SE_NC_1` setpoint writes and fires Notices when a protection pickup is changed - and, specifically, when a 51P overcurrent pickup is dropped below a safe floor.

---

## How it works

- **Hook.** The script handles Zeek's `packet_contents` event and filters to connections where either endpoint is on port 2404. It also logs a one-time `conn` row per new IEC-104 connection via `connection_established`.
- **APDU framing.** Each payload can carry several back-to-back APDUs. The parser scans for the `0x68` start byte, reads the length field, and processes one complete APDU at a time until the buffer is exhausted.
- **Frame type.** The low bits of the first control field select the format:
  - **U-frame** (link control): STARTDT / STOPDT / TESTFR act/con are each
    logged as a control row.
  - **S-frame** (supervisory ack): logged with the acknowledged sequence number.
  - **I-frame** (information): the ASDU is decoded.
- **ASDU decode.** From the ASDU the script reads TypeID, VSQ (object count + the SQ sequential-addressing bit), the 2-byte COT (cause in the low 6 bits), and the Common Address, then walks the information objects.
- **Object walking.** It supports single- and multi-object ASDUs in both addressing modes: SQ=0 (each object carries its own IOA) and SQ=1 (one base IOA, then values back-to-back at IOA, IOA+1, IOA+2, …). Each object is emitted as its own log row. Truncated/short ASDUs are handled without reading past the buffer.
- **Nothing is silently dropped.** U-frames, S-frames, and ASDUs with an unrecognized TypeID each still produce a log row (the unknown TypeID gets a single summary row with the raw ASDU hex), which is what lets you spot negative confirmations and truly unexpected traffic.

---

## What it decodes

**TypeIDs** (monitoring and control):

- Monitoring, no time tag: M_SP_NA_1 (1), M_DP_NA_1 (3), M_ST_NA_1 (5), M_BO_NA_1 (7), M_ME_NA_1 (9), M_ME_NB_1 (11), M_ME_NC_1 (13).
- Monitoring, CP56Time2a-tagged: types 30–36 (the time-tagged twins of the above).
- Control: C_SC_NA_1 (45), C_DC_NA_1 (46), C_RC_NA_1 (47), C_SE_NA_1 (48), C_SE_NB_1 (49), C_SE_NC_1 (50), C_BO_NA_1 (51).
- System/other: M_EI_NA_1 (70), C_IC_NA_1 (100, interrogation), C_CS_NA_1 (103, clock sync), and TypeID 104 (test command).

**Semantic decoding on top of the raw bytes:**

- **Boolean points/commands** (single- and double-point, single/double/step commands): decoded to On`/`Off`/`Lower`/`Higher`/`Indeterminate` in `spi_desc`.
- **CP56Time2a timestamps** (clock sync, test command, and every time-tagged monitoring type): decoded to `YYYY-MM-DD HH:MM:SS.mmm` in `clock_ts`, with the correct per-type offset to the time field.
- **Interrogation**: the QOI (station vs group) is noted.
- **Cause of Transmission**: mapped to short names - Spont (3), Act (6), ActCon (7), Term (10), Inrogen (20), and the Unknown* negative causes (44–47).
- **IOA names**: each IOA is labeled from a lookup table (`ioa_names`) carrying the lab RTU point map - e.g. IOA 1 = Breaker Position, IOA 3 = 51P Overcurrent Trip, IOA 101 = Phase A Current, IOA 501 = 51P Phase Time Overcurrent Pickup.
- **Raw value**: every decoded object also carries `value_hex`, the exact information-element bytes. This is ground truth even when no higher-level decode applies - and it is what exposes the numeric value of a setpoint write
  (e.g. a short-float `200.0`).

---

## The `iec104.log` fields

| Field | Meaning |
|---|---|
| `ts`, `uid` | Timestamp and Zeek connection UID |
| `id_orig_h/_p`, `id_resp_h/_p` | Connection originator and responder (see note below) |
| `apdu_dir` | Direction marker (`orig->resp`) |
| `apdu_type` | `I`, `S`, `U`, or `conn` |
| `typeid`, `type_desc` | ASDU TypeID and its name |
| `cot`, `cot_desc` | Cause of transmission (number and name) |
| `common_addr` | Common (station) address |
| `ioa`, `ioa_desc` | Information object address and its point name |
| `num_obj`, `sq` | Objects in the ASDU; sequential-addressing flag |
| `spi_val`, `spi_desc` | Decoded boolean value/label for points and commands |
| `clock_ts` | Decoded CP56Time2a timestamp |
| `value_hex` | Raw information-element bytes (always populated for decoded objects) |
| `note` | One-line human-readable summary of the row |

> **Direction note.** The `packet_contents` hook does not tell the script which
> side sent a packet, so `id_orig_h` is always the connection originator and
> `apdu_dir` is fixed. Infer the real direction from the COT instead: COT 6
> (Act) comes from the client/HMI; COT 7/10/20/3/44 come from the RTU.

---

## Protection-setpoint Notices

Beyond logging, the script watches for the one action that looks completely normal on the wire but changes how a relay behaves: a setpoint write. It raises:
- **`IEC104::Protection_Setpoint_Write`** - any `C_SE_NC_1` (TypeID 50) activation write to a protection-setpoint IOA (501–504). On the modeled hardware these points are not remotely writable at all, so any such write is anomalous by construction, whatever the source.
- **`IEC104::Protection_Setpoint_Below_Floor`** - a 51P overcurrent pickup (IOA 501) written *below* the target RTU's legitimate value. The script decodes the 4-byte IEEE-754 float and compares it against a per-RTU floor in  `pickup_floor_bits`. (For positive floats, comparing the raw 32-bit patterns as integers preserves numeric order, so no floating-point math is needed.)

These Notices land in Zeek's `notice.log` (ingested as `zeek.notice` in Security Onion) and fire even when the write comes from the authorized HMI - which is exactly the case signature-by-source rules cannot catch.

---

## Configuration

All of these are `&redef`-able from your own site policy:
- **`IEC104::ioa_names`** - IOA → point-name table. Extend or replace it to match
  your point list.
- **`IEC104::pickup_floor_bits`** - per-RTU legitimate 51P pickup floors, keyed
  by RTU IP, as IEEE-754 bit patterns (600 A = `0x44160000`, 800 A =
  `0x44480000`, 1200 A = `0x44960000`). Edit for your addressing:
  ```zeek
  redef IEC104::pickup_floor_bits += { [10.0.0.5] = 0x44160000 };  # 600.0 A
  ```
- **`IEC104::value_len_table`** - information-element length per TypeID; add
  entries to teach the parser new types.
- **`IEC104::log_iec104`** - set to `F` to disable logging.

---

## Known limitations
1. **No direction flag** - inferred from COT, as noted above.
2. **Packet-level, not stream-reassembled** - an APDU split across two TCP segments is not reassembled. Tools that send one APDU per segment (and most lab traffic) are unaffected; some production links pack or split APDUs.
3. **Numeric measured/setpoint values** appear as `value_hex` (and, for IOA 501, are decoded inside the Notice logic); other floats are not expanded into a numeric field.
4. **TypeID 104** is labeled per the lab convention; the IEC standard names TypeID 104 `C_TS_NA_1` (with `C_TS_TA_1` being 107). Cosmetic only.

---

## Example rows (illustrative)

A setpoint write that drops IOA 501 to 200.0 A:

```
typeid=50 type_desc="C_SE_NC_1 setpoint command, short float" cot=6 cot_desc=Act
ioa=501 ioa_desc="51P Phase Time Overcurrent Pickup" value_hex=0000484300
note="C_SE_NC_1 ... IOA=501 (51P Phase Time Overcurrent Pickup) COT=6 (Act) value=0x0000484300"
```

(`00 00 48 43` little-endian = IEEE-754 `200.0`.) Alongside it, in `notice.log`:

```
IEC104::Protection_Setpoint_Write          C_SE_NC_1 write to protection setpoint IOA 501 ...
IEC104::Protection_Setpoint_Below_Floor    51P pickup on 172.16.111.101 set below legitimate floor ...
```

A breaker status point in an interrogation reply:

```
typeid=1 type_desc="M_SP_NA_1 single-point information" cot=20 cot_desc=Inrogen
ioa=1 ioa_desc="Breaker Position" sq=T spi_val=0 spi_desc=Off note="... value=0x00"
```

---

## Usage

Load it like any Zeek script or package:

```
# one-off, against a capture
zeek -b -r your_iec104.pcap scripts/iec_104.zeek

# as an installed package
zkg install .
```

It writes `iec104.log` (and, on setpoint tampering, entries in `notice.log`) to
Zeek's current log directory. Requires Zeek >= 4.0.0; no external dependencies.
