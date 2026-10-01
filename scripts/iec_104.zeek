# File: iec_104.zeek
# IEC 60870-5-104 parser for the reassembled TCP/2404 stream.
#
# COURSE-CORRECTED EDITION. Changes from the originally distributed script:
#   1. ioa_names now reflects the lab RTU point map (Chapter 2 / Lab 3A Task 2)
#      instead of the placeholder "Feeder A-F Breaker" labels.
#   2. Adds value-aware protection-setpoint Notices (Chapter 3, Lab 3D): an
#      IEC104::Protection_Setpoint_Write for any C_SE_NC_1 write to IOA 501-504,
#      and an IEC104::Protection_Setpoint_Below_Floor when a 51P pickup (IOA 501)
#      is written below the target RTU's legitimate floor. The floors are keyed
#      by RTU IP in pickup_floor_bits below -- edit that table for your own
#      addressing before deploying outside the lab.
#
# v3 (long-lived session support):
#   3. Parses the reassembled TCP stream (tcp_contents) instead of raw
#      per-packet payloads (packet_contents). As a result:
#        - apdu_dir is the real direction ("orig->resp" or "resp->orig").
#          It was previously hard-coded to "orig->resp" for every frame,
#          so every RTU reply was mislabeled.
#        - TCP retransmissions no longer produce duplicate log rows.
#        - An APDU split across segments, or several APDUs packed into one
#          segment, are both parsed correctly.
#        - Only TCP/2404 is delivered to the script, which is much cheaper
#          than raising packet_contents for every packet on the sensor.
#   4. iec104.log gains ns / nr (APCI send / receive sequence numbers, the
#      N(S) and N(R) of Chapter 1) and negative (the COT P/N bit).
#   5. IEC104::Sequence_Discontinuity Notice when N(S) jumps within one
#      session and direction. On a long-lived session this is an injection /
#      hijack indicator. Capture loss (Zeek content_gap) re-baselines the
#      check instead of alerting. In the lab, every HMI action is a fresh
#      session starting at N(S)=0, so this Notice should stay silent.
#   6. iec104_cmd.log: one row per command transaction, the IEC-104
#      counterpart of http.log. A request (COT 6 Act or 8 Deact) is paired
#      with its replies (ActCon / DeactCon / ActTerm, or a COT 44-47
#      rejection) and written once the outcome is known:
#        result = terminated   positive ActCon, then ActTerm
#                 confirmed    positive ActCon, no ActTerm before term_wait
#                              (normal for the lab RTU and for clock sync)
#                 rejected     negative ActCon, or COT 44-47 (reject_cause)
#                 deactivated  Deact acknowledged by DeactCon
#                 no_response  no confirmation within confirm_timeout (t1)
#      A row is never held past confirm_timeout / term_wait or the end of
#      the TCP session, so long-lived sessions still log promptly.
#      New Elastic ingest pipeline required: zeek.iec104_cmd.
#   7. cot_desc covers the full standard COT range (adds 1-5, 8, 9, 11-13,
#      21-41); typeid_desc adds the time-tagged commands and other system
#      commands so they are named in iec104_cmd.log.
#
# v2 (retained from original): covers all common monitoring TypeIDs
# (1,3,5,7,9,11,13) and their CP56-tagged counterparts (30-36); all common
# command TypeIDs (45-51), test command (70), interrogation (100), clock sync
# (103); multi-object ASDUs (VSQ count>1, SQ=0 and SQ=1); U-frames and
# S-frames each get a log row; unrecognized TypeIDs get one summary row.
#
# Every object logged carries a raw value_hex field regardless of type, plus
# best-effort semantic decode (spi_val/spi_desc for boolean-style points and
# commands, clock_ts for anything carrying a CP56Time2a) where the format is
# known. Measured/setpoint numeric values (normalized/scaled/short-float) are
# exposed via value_hex; the Lab 3D Notices above decode the short-float
# setpoint value for threshold comparison, and iec104_cmd.log decodes
# setpoint values into value_num.
#
# Compatible with older Zeek (no nested local redefs, etc.). v3 tested on
# Zeek 7.0.9.

@load base/frameworks/notice

module IEC104;

export {
    const log_iec104 = T &redef;

    ## Write iec104_cmd.log (command transactions).
    const log_iec104_cmd = T &redef;

    ## Raise IEC104::Sequence_Discontinuity on N(S) jumps.
    const check_sequence = T &redef;

    ## How long to wait for ActCon/DeactCon before logging no_response.
    ## IEC 60870-5-104 default t1 = 15 s.
    const confirm_timeout = 15 sec &redef;

    ## After a positive ActCon, how long to wait for an optional ActTerm on
    ## commands (TypeIDs 45-51, 58-64) before logging result=confirmed.
    const term_wait = 10 sec &redef;

    ## After a positive ActCon, how long to wait for the ActTerm that closes
    ## a station/group or counter interrogation (TypeIDs 100, 101).
    const interrogation_term_wait = 60 sec &redef;

    redef enum Log::ID += { LOG, CMD_LOG };

    ## Value-aware protection-setpoint notices (Lab 3D) and the v3
    ## sequence-continuity notice.
    redef enum Notice::Type += {
        Protection_Setpoint_Write,
        Protection_Setpoint_Below_Floor,
        Sequence_Discontinuity
    };

    ## Legitimate 51P pickup per RTU, as raw IEEE-754 single-precision bit
    ## patterns (positive floats compare correctly as unsigned integers):
    ##   600.0 A = 0x44160000   800.0 A = 0x44480000   1200.0 A = 0x44960000
    ## Edit these addresses/values for your own deployment.
    const pickup_floor_bits: table[addr] of count = {
        [172.16.111.101] = 0x44160000,   # RTU-A, 600.0 A
        [172.16.111.102] = 0x44480000,   # RTU-B, 800.0 A
        [172.16.111.103] = 0x44960000    # RTU-C, 1200.0 A
    } &redef;

    type Info: record {
        ts:          time   &log;
        uid:         string &log;
        id_orig_h:   addr   &log;
        id_orig_p:   port   &log;
        id_resp_h:   addr   &log;
        id_resp_p:   port   &log;

        apdu_dir:    string &log &optional;  # "orig->resp" or "resp->orig"
        apdu_type:   string &log &optional;  # "I","S","U","conn"

        ns:          count  &log &optional;  # N(S), I-frames only
        nr:          count  &log &optional;  # N(R), I- and S-frames

        typeid:      count  &log &optional;
        type_desc:   string &log &optional;

        cot:         count  &log &optional;  # Cause of transmission (6 bits)
        cot_desc:    string &log &optional;
        negative:    bool   &log &optional;  # COT P/N bit (negative confirm)

        common_addr: count  &log &optional;
        ioa:         count  &log &optional;
        ioa_desc:    string &log &optional;

        num_obj:     count  &log &optional;  # objects in this ASDU (VSQ count)
        sq:          bool   &log &optional;  # T = sequential addressing (SQ=1)

        spi_val:     count  &log &optional;  # boolean-style point/command value
        spi_desc:    string &log &optional;  # e.g. "On"/"Off"/"Lower"/"Higher"

        ## Clock sync / time-tagged timestamp (decoded CP56Time2a)
        clock_ts:    string &log &optional;

        ## Raw info-element bytes (value, excluding IOA), always populated
        ## when an object is successfully decoded -- ground truth even when
        ## no semantic decode above applies.
        value_hex:   string &log &optional;

        note:        string &log &optional;
    };

    ## One row per command transaction (iec104_cmd.log).
    type CmdInfo: record {
        ts:            time     &log;           # time of the request
        uid:           string   &log;
        id_orig_h:     addr     &log;
        id_orig_p:     port     &log;
        id_resp_h:     addr     &log;
        id_resp_p:     port     &log;

        cmd_dir:       string   &log;           # direction the request travelled
        request:       string   &log;           # "Act" (COT 6) or "Deact" (COT 8)
        ns:            count    &log;           # N(S) of the request APDU

        typeid:        count    &log;
        type_desc:     string   &log;
        common_addr:   count    &log;
        ioa:           count    &log;
        ioa_desc:      string   &log;

        cmd_desc:      string   &log &optional; # "On"/"Off", "QOI=20 station", setpoint, clock
        se:            string   &log &optional; # "select" or "execute" (S/E bit, TypeIDs 45-50)
        value_num:     double   &log &optional; # decoded setpoint (TypeIDs 48-50)
        value_hex:     string   &log &optional; # raw info element of the request

        result:        string   &log;           # see header for values
        reject_cause:  string   &log &optional;
        confirm_delay: interval &log &optional; # request -> ActCon/DeactCon/rejection
        terminated:    bool     &log;           # ActTerm seen
        term_delay:    interval &log &optional; # request -> ActTerm
        resp_objects:  count    &log &optional; # objects returned by an interrogation

        ## Internal state, not logged.
        req_is_orig:   bool;
        confirmed:     bool     &default=F;
        tid:           count;
        qbase:         string;
    };

    ## IOA -> human-readable name. Matches the lab RTU point map (Chapter 2);
    ## all three RTUs share the same IOA scheme.
    const ioa_names: table[count] of string = {
        [1]   = "Breaker Position",
        [2]   = "51P Overcurrent Timing",
        [3]   = "51P Overcurrent Trip Any Pole",
        [4]   = "50P Instantaneous Overcurrent Trip",
        [5]   = "51N/G Ground Overcurrent Trip",
        [6]   = "Breaker Failure 50BF Trip",
        [7]   = "Local/Remote Control Status",
        [101] = "Phase A Current",
        [102] = "Phase B Current",
        [103] = "Phase C Current",
        [104] = "Ground/Residual Current",
        [105] = "Real-Time Feeder Loading",
        [501] = "51P Phase Time Overcurrent Pickup",
        [502] = "50P Phase Instantaneous Overcurrent Pickup",
        [503] = "51N/G Ground Overcurrent Pickup",
        [504] = "Time Dial / Curve Multiplier"
    } &redef;

    ## Length (in bytes) of the info element / value for each known ASDU
    ## TypeID, NOT including the 3-byte IOA. Types not present here are
    ## treated as unrecognized (logged as a single summary row, no per-object
    ## decode attempted).
    const value_len_table: table[count] of count = {
        # -- monitoring, no time tag --
        [1]  = 1,  # M_SP_NA_1  SIQ
        [3]  = 1,  # M_DP_NA_1  DIQ
        [5]  = 2,  # M_ST_NA_1  VTI + QDS
        [7]  = 5,  # M_BO_NA_1  BSI(4) + QDS
        [9]  = 3,  # M_ME_NA_1  NVA(2) + QDS
        [11] = 3,  # M_ME_NB_1  SVA(2) + QDS
        [13] = 5,  # M_ME_NC_1  FLOAT(4) + QDS
        # -- monitoring, CP56-tagged --
        [30] = 8,  # M_SP_TB_1  SIQ(1) + CP56(7)
        [31] = 8,  # M_DP_TB_1  DIQ(1) + CP56(7)
        [32] = 9,  # M_ST_TB_1  VTI+QDS(2) + CP56(7)
        [33] = 12, # M_BO_TB_1  BSI+QDS(5) + CP56(7)
        [34] = 10, # M_ME_TD_1  NVA+QDS(3) + CP56(7)
        [35] = 10, # M_ME_TE_1  SVA+QDS(3) + CP56(7)
        [36] = 12, # M_ME_TF_1  FLOAT+QDS(5) + CP56(7)
        # -- commands --
        [45] = 1,  # C_SC_NA_1  SCS
        [46] = 1,  # C_DC_NA_1  DCS
        [47] = 1,  # C_RC_NA_1  RCS
        [48] = 3,  # C_SE_NA_1  NVA(2) + QOS
        [49] = 3,  # C_SE_NB_1  SVA(2) + QOS
        [50] = 5,  # C_SE_NC_1  FLOAT(4) + QOS
        [51] = 4,  # C_BO_NA_1  BSI(4)
        # -- system / misc --
        [70]  = 1,  # M_EI_NA_1  COI (1 byte) -- NOT a test command; confirmed
                    # against real traffic/Wireshark. Our own lab client/server
                    # previously modeled "Test Command" on TypeID 70 with a
                    # 7-byte CP56 payload, which collides with this real type
                    # and its actual (much shorter) structure.
        [100] = 1,  # C_IC_NA_1  QOI, fixed IOA=0
        [103] = 7,  # C_CS_NA_1  CP56(7), fixed IOA=0
        [104] = 7,  # C_TS_TA_1  the REAL test command: CP56(7), fixed IOA=0
    } &redef;
}

## Deliver the reassembled TCP/2404 stream, both directions, to tcp_contents.
redef tcp_content_delivery_ports_orig += { [2404/tcp] = T };
redef tcp_content_delivery_ports_resp += { [2404/tcp] = T };

## ---------------- Internal state ----------------

## Fields shared by every object in one APDU.
type ApduCtx: record {
    is_orig:  bool;
    dir:      string;
    ns:       count;
    nr:       count;
    typeid:   count;
    cot:      count;    # 6-bit cause
    negative: bool;     # P/N bit
    common:   count;
    num_obj:  count;
    sq:       bool;
};

## Partial APDU carried over between stream deliveries, per direction.
global rx_buf: table[string] of string &read_expire = 1 day;

## Next expected N(S), per direction.
global next_ns: table[string] of count &read_expire = 1 day;

## Command transactions awaiting their outcome. A master may send a second
## request before the first is confirmed (replies then arrive in order), so
## open requests are queued per "base" key (session, common address,
## TypeID, IOA, Act/Deact). Each entry is stored as "<base>#<n>"; q_head and
## q_tail hold the oldest possibly-open n and the next n to assign.
global pending: table[string] of CmdInfo;
global q_head: table[string] of count;
global q_tail: table[string] of count;
global cmd_counter: count = 0;

global cmd_timer: event(key: string, term_stage: bool);

## ---------------- Helper functions ----------------

function get_byte(data: string, pos: count): count
    {
    return bytestring_to_count(sub_bytes(data, pos, 1));
    }

function get_le16(data: string, pos: count): count
    {
    local b0: count = get_byte(data, pos);
    local b1: count = get_byte(data, pos + 1);
    return b0 + (b1 << 8);
    }

function get_le24(data: string, pos: count): count
    {
    local b0: count = get_byte(data, pos);
    local b1: count = get_byte(data, pos + 1);
    local b2: count = get_byte(data, pos + 2);
    return b0 + (b1 << 8) + (b2 << 16);
    }

function get_le32(data: string, pos: count): count
    {
    local b0: count = get_byte(data, pos);
    local b1: count = get_byte(data, pos + 1);
    local b2: count = get_byte(data, pos + 2);
    local b3: count = get_byte(data, pos + 3);
    return b0 + (b1 << 8) + (b2 << 16) + (b3 << 24);
    }

## Signed 16-bit little-endian value as a double.
function get_le16_signed(data: string, pos: count): double
    {
    local v: count = get_le16(data, pos);
    local d: double = count_to_double(v);
    if ( v >= 32768 )
        d = d - 65536.0;
    return d;
    }

## T if an IEEE-754 single-precision bit pattern is a finite number.
function f32_is_finite(bits: count): bool
    {
    return ((bits >> 23) & 0xff) != 0xff;
    }

## IEEE-754 single-precision bit pattern -> double (finite values only).
function f32_to_double(bits: count): double
    {
    local sign: count = (bits >> 31) & 0x1;
    local e: count = (bits >> 23) & 0xff;
    local mant: count = bits & 0x7fffff;
    local d: double;

    if ( e == 0 )
        {
        # zero or subnormal: mant * 2^-149
        d = count_to_double(mant) * 1.401298464324817e-45;
        return sign == 1 ? -d : d;
        }

    # Re-bias the exponent and widen the mantissa into a double's bit layout.
    local dbits: count = (sign << 63) | ((e + 896) << 52) | (mant << 29);
    return bytestring_to_double(hexstr_to_bytestring(fmt("%016x", dbits)));
    }

function dir_str(is_orig: bool): string
    {
    return is_orig ? "orig->resp" : "resp->orig";
    }

function dir_key(c: connection, is_orig: bool): string
    {
    return cat(c$uid, is_orig ? "/o" : "/r");
    }

function is_iec104(c: connection): bool
    {
    return c$id$orig_p == 2404/tcp || c$id$resp_p == 2404/tcp;
    }

function typeid_desc(t: count): string
    {
    if ( t == 1 )   return "M_SP_NA_1 single-point information";
    if ( t == 3 )   return "M_DP_NA_1 double-point information";
    if ( t == 5 )   return "M_ST_NA_1 step position information";
    if ( t == 7 )   return "M_BO_NA_1 bitstring";
    if ( t == 9 )   return "M_ME_NA_1 measured value, normalized";
    if ( t == 11 )  return "M_ME_NB_1 measured value, scaled";
    if ( t == 13 )  return "M_ME_NC_1 measured value, short float";
    if ( t == 30 )  return "M_SP_TB_1 single-point + CP56Time2a";
    if ( t == 31 )  return "M_DP_TB_1 double-point + CP56Time2a";
    if ( t == 32 )  return "M_ST_TB_1 step position + CP56Time2a";
    if ( t == 33 )  return "M_BO_TB_1 bitstring + CP56Time2a";
    if ( t == 34 )  return "M_ME_TD_1 measured, normalized + CP56Time2a";
    if ( t == 35 )  return "M_ME_TE_1 measured, scaled + CP56Time2a";
    if ( t == 36 )  return "M_ME_TF_1 measured, short float + CP56Time2a";
    if ( t == 45 )  return "C_SC_NA_1 single command";
    if ( t == 46 )  return "C_DC_NA_1 double command";
    if ( t == 47 )  return "C_RC_NA_1 regulating step command";
    if ( t == 48 )  return "C_SE_NA_1 setpoint command, normalized";
    if ( t == 49 )  return "C_SE_NB_1 setpoint command, scaled";
    if ( t == 50 )  return "C_SE_NC_1 setpoint command, short float";
    if ( t == 51 )  return "C_BO_NA_1 bitstring command";
    if ( t == 58 )  return "C_SC_TA_1 single command + CP56Time2a";
    if ( t == 59 )  return "C_DC_TA_1 double command + CP56Time2a";
    if ( t == 60 )  return "C_RC_TA_1 regulating step command + CP56Time2a";
    if ( t == 61 )  return "C_SE_TA_1 setpoint, normalized + CP56Time2a";
    if ( t == 62 )  return "C_SE_TB_1 setpoint, scaled + CP56Time2a";
    if ( t == 63 )  return "C_SE_TC_1 setpoint, short float + CP56Time2a";
    if ( t == 64 )  return "C_BO_TA_1 bitstring command + CP56Time2a";
    if ( t == 70 )  return "M_EI_NA_1 end of initialization";
    if ( t == 100 ) return "C_IC_NA_1 interrogation command";
    if ( t == 101 ) return "C_CI_NA_1 counter interrogation command";
    if ( t == 102 ) return "C_RD_NA_1 read command";
    if ( t == 103 ) return "C_CS_NA_1 clock sync";
    if ( t == 104 ) return "C_TS_TA_1 test command";
    if ( t == 105 ) return "C_RP_NA_1 reset process command";
    if ( t == 107 ) return "C_TS_TA_1 test command + CP56Time2a";

    return fmt("TypeID 0x%02x (unrecognized)", t);
    }

function cot_desc(c: count): string
    {
    if ( c == 1 )  return "Per/Cyc";
    if ( c == 2 )  return "Back";
    if ( c == 3 )  return "Spont";
    if ( c == 4 )  return "Init";
    if ( c == 5 )  return "Req";
    if ( c == 6 )  return "Act";
    if ( c == 7 )  return "ActCon";
    if ( c == 8 )  return "Deact";
    if ( c == 9 )  return "DeactCon";
    if ( c == 10 ) return "Term";
    if ( c == 11 ) return "Retrem";
    if ( c == 12 ) return "Retloc";
    if ( c == 13 ) return "File";
    if ( c == 20 ) return "Inrogen";
    if ( c >= 21 && c <= 36 ) return fmt("Inro%d", c - 20);
    if ( c == 37 ) return "Reqcogen";
    if ( c >= 38 && c <= 41 ) return fmt("Reqco%d", c - 37);
    if ( c == 44 ) return "UnknownType";
    if ( c == 45 ) return "UnknownCause";
    if ( c == 46 ) return "UnknownAddr";
    if ( c == 47 ) return "UnknownIOA";

    return fmt("COT %d", c);
    }

function ioa_desc(ioa: count): string
    {
    if ( ioa in ioa_names )
        return ioa_names[ioa];

    return fmt("IOA %d", ioa);
    }

## Decode CP56Time2a at 'pos' (1-based) into string "YYYY-MM-DD HH:MM:SS.mmm"
function decode_cp56time2a(data: string, pos: count): string
    {
    if ( pos + 6 > |data| )
        return "<invalid CP56Time2a>";

    local ms_low:  count = get_byte(data, pos);
    local ms_high: count = get_byte(data, pos + 1);
    local ms_total: count = ms_low + (ms_high << 8);

    local ms:   count = ms_total % 1000;
    local sec:  count = ms_total / 1000;
    local min:  count = get_byte(data, pos + 2) & 0x3f;
    local hour: count = get_byte(data, pos + 3) & 0x1f;
    local mday: count = get_byte(data, pos + 4) & 0x1f;
    local mon:  count = get_byte(data, pos + 5) & 0x0f;
    local year: count = (get_byte(data, pos + 6) & 0x7f) + 2000;

    return fmt("%04d-%02d-%02d %02d:%02d:%02d.%03d",
               year, mon, mday, hour, min, sec, ms);
    }

## Common leading fields of an iec104.log row.
function base_info(c: connection): Info
    {
    return Info($ts=network_time(), $uid=c$uid,
                $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
                $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p);
    }

## ---------------- Logging setup ----------------

event zeek_init()
    {
    if ( log_iec104 )
        Log::create_stream(IEC104::LOG, [$columns=Info, $path="iec104"]);

    if ( log_iec104_cmd )
        Log::create_stream(IEC104::CMD_LOG, [$columns=CmdInfo, $path="iec104_cmd"]);
    }

event connection_established(c: connection)
    {
    if ( ! log_iec104 )
        return;

    if ( ! is_iec104(c) )
        return;

    local info = base_info(c);
    info$apdu_type = "conn";
    info$typeid = 0;
    info$type_desc = "IEC104 connection";
    info$note = "IEC104 connection established";
    Log::write(IEC104::LOG, info);
    }

## ---------------- Command transactions (iec104_cmd.log) ----------------

function cmd_key(uid: string, common: count, typeid: count, ioa: count, req: string): string
    {
    return fmt("%s|%d|%d|%d|%s", uid, common, typeid, ioa, req);
    }

## Does this TypeID normally (or optionally) send an ActTerm after ActCon?
function term_expected(typeid: count): bool
    {
    return (typeid >= 45 && typeid <= 51) || (typeid >= 58 && typeid <= 64)
           || typeid == 100 || typeid == 101;
    }

## Write a transaction row, forget it, and trim its queue.
function cmd_finish(key: string)
    {
    if ( key !in pending )
        return;

    local base: string = pending[key]$qbase;

    Log::write(IEC104::CMD_LOG, pending[key]);
    delete pending[key];

    if ( base !in q_head )
        return;

    while ( q_head[base] < q_tail[base] &&
            fmt("%s#%d", base, q_head[base]) !in pending )
        ++q_head[base];

    if ( q_head[base] >= q_tail[base] )
        {
        delete q_head[base];
        delete q_tail[base];
        }
    }

## Write every open transaction of one session (or of all sessions when
## uid is ""), oldest request first.
function cmd_flush(uid: string)
    {
    local by_tid: table[count] of string;
    local tids: vector of count = vector();

    for ( k in pending )
        if ( uid == "" || pending[k]$uid == uid )
            {
            by_tid[pending[k]$tid] = k;
            tids[|tids|] = pending[k]$tid;
            }

    sort(tids);

    for ( i in tids )
        cmd_finish(by_tid[tids[i]]);
    }

## Oldest open request queued under 'base' that a reply travelling in the
## direction 'reply_is_orig' can belong to. mode:
##   "unconfirmed" -> not yet confirmed (ActCon, DeactCon, COT 44-47)
##   "confirmed"   -> already confirmed (interrogation data)
##   "any"         -> any open request (ActTerm)
function oldest_open(base: string, reply_is_orig: bool, mode: string): string
    {
    if ( base !in q_head )
        return "";

    local n: count = q_head[base];
    local k: string;

    while ( n < q_tail[base] )
        {
        k = fmt("%s#%d", base, n);
        if ( k in pending && pending[k]$req_is_orig != reply_is_orig )
            {
            if ( mode == "any" )
                return k;
            if ( mode == "unconfirmed" && ! pending[k]$confirmed )
                return k;
            if ( mode == "confirmed" && pending[k]$confirmed )
                return k;
            }
        ++n;
        }

    return "";
    }

## Semantic decode of a command's info element.
function describe_command(ci: CmdInfo, typeid: count, value: string)
    {
    local n: count = |value|;
    local b0: count;
    local qos: count;
    local bits: count;
    local qoi: count;

    if ( n == 0 )
        return;

    b0 = get_byte(value, 1);

    if ( typeid == 45 )
        {
        ci$cmd_desc = (b0 & 0x01) == 1 ? "On" : "Off";
        ci$se = (b0 & 0x80) != 0 ? "select" : "execute";
        }
    else if ( typeid == 46 || typeid == 47 )
        {
        if ( (b0 & 0x03) == 1 )
            ci$cmd_desc = typeid == 46 ? "Off" : "Lower";
        else if ( (b0 & 0x03) == 2 )
            ci$cmd_desc = typeid == 46 ? "On" : "Higher";
        else
            ci$cmd_desc = "Not permitted";
        ci$se = (b0 & 0x80) != 0 ? "select" : "execute";
        }
    else if ( (typeid == 48 || typeid == 49) && n >= 3 )
        {
        if ( typeid == 48 )
            ci$value_num = get_le16_signed(value, 1) / 32768.0;
        else
            ci$value_num = get_le16_signed(value, 1);
        ci$cmd_desc = fmt("setpoint %.4f", ci$value_num);
        qos = get_byte(value, 3);
        ci$se = (qos & 0x80) != 0 ? "select" : "execute";
        }
    else if ( typeid == 50 && n >= 5 )
        {
        bits = get_le32(value, 1);
        if ( f32_is_finite(bits) )
            {
            ci$value_num = f32_to_double(bits);
            ci$cmd_desc = fmt("setpoint %.4f", ci$value_num);
            }
        else
            ci$cmd_desc = fmt("setpoint non-finite (0x%08x)", bits);
        qos = get_byte(value, 5);
        ci$se = (qos & 0x80) != 0 ? "select" : "execute";
        }
    else if ( typeid == 51 && n >= 4 )
        ci$cmd_desc = fmt("BSI=0x%08x", get_le32(value, 1));
    else if ( typeid == 100 )
        {
        qoi = b0;
        if ( qoi == 20 )
            ci$cmd_desc = "QOI=20 station";
        else if ( qoi >= 21 && qoi <= 36 )
            ci$cmd_desc = fmt("QOI=%d group %d", qoi, qoi - 20);
        else
            ci$cmd_desc = fmt("QOI=%d", qoi);
        }
    else if ( typeid == 103 )
        ci$cmd_desc = decode_cp56time2a(value, 1);
    else if ( typeid == 104 )
        ci$cmd_desc = "test";
    }

## A request: COT 6 (Act) or COT 8 (Deact).
function cmd_request(c: connection, ctx: ApduCtx, ioa: count, value: string)
    {
    local req: string = ctx$cot == 6 ? "Act" : "Deact";
    local base: string = cmd_key(c$uid, ctx$common, ctx$typeid, ioa, req);

    if ( base !in q_tail )
        {
        q_head[base] = 0;
        q_tail[base] = 0;
        }

    local key: string = fmt("%s#%d", base, q_tail[base]);
    ++q_tail[base];
    ++cmd_counter;

    local ci = CmdInfo($ts=network_time(), $uid=c$uid,
                       $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
                       $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p,
                       $cmd_dir=ctx$dir, $request=req, $ns=ctx$ns,
                       $typeid=ctx$typeid, $type_desc=typeid_desc(ctx$typeid),
                       $common_addr=ctx$common, $ioa=ioa, $ioa_desc=ioa_desc(ioa),
                       $result="no_response", $terminated=F,
                       $req_is_orig=ctx$is_orig, $tid=cmd_counter, $qbase=base);

    if ( |value| > 0 )
        ci$value_hex = bytestring_to_hexstr(value);

    if ( ctx$typeid == 100 || ctx$typeid == 101 )
        ci$resp_objects = 0;

    describe_command(ci, ctx$typeid, value);
    pending[key] = ci;

    schedule confirm_timeout { IEC104::cmd_timer(key, F) };
    }

## Find the open request a reply belongs to. COT 44-47 rejections may not
## echo the IOA (the lab RTU sends IOA 0), so those fall back to the oldest
## unconfirmed request with the same TypeID and common address.
function find_pending(c: connection, ctx: ApduCtx, ioa: count, req: string, mode: string): string
    {
    local key: string = oldest_open(cmd_key(c$uid, ctx$common, ctx$typeid, ioa, req),
                                    ctx$is_orig, mode);

    if ( key != "" || ctx$cot < 44 || ctx$cot > 47 )
        return key;

    local best: string = "";
    local best_tid: count = 0;

    for ( k in pending )
        {
        local ci = pending[k];
        if ( ci$uid == c$uid && ci$common_addr == ctx$common &&
             ci$typeid == ctx$typeid && ci$request == req &&
             ci$req_is_orig != ctx$is_orig && ! ci$confirmed &&
             (best == "" || ci$tid < best_tid) )
            {
            best = k;
            best_tid = ci$tid;
            }
        }

    return best;
    }

## A reply: COT 7 (ActCon), 9 (DeactCon), 10 (ActTerm) or 44-47 (rejection).
function cmd_response(c: connection, ctx: ApduCtx, ioa: count)
    {
    local cot: count = ctx$cot;
    local key: string = "";

    if ( cot == 7 )
        key = find_pending(c, ctx, ioa, "Act", "unconfirmed");
    else if ( cot == 9 )
        key = find_pending(c, ctx, ioa, "Deact", "unconfirmed");
    else if ( cot == 10 )
        key = find_pending(c, ctx, ioa, "Act", "any");
    else
        {
        key = find_pending(c, ctx, ioa, "Act", "unconfirmed");
        if ( key == "" )
            key = find_pending(c, ctx, ioa, "Deact", "unconfirmed");
        }

    if ( key == "" )
        return;

    local ci = pending[key];
    local now: time = network_time();

    if ( cot == 7 || cot == 9 )
        {
        ci$confirmed = T;
        ci$confirm_delay = now - ci$ts;

        if ( ctx$negative )
            {
            ci$result = "rejected";
            ci$reject_cause = cot == 7 ? "negative ActCon" : "negative DeactCon";
            cmd_finish(key);
            return;
            }

        if ( cot == 9 )
            {
            ci$result = "deactivated";
            cmd_finish(key);
            return;
            }

        ci$result = "confirmed";

        if ( ! term_expected(ci$typeid) )
            {
            cmd_finish(key);
            return;
            }

        if ( ci$typeid == 100 || ci$typeid == 101 )
            schedule interrogation_term_wait { IEC104::cmd_timer(key, T) };
        else
            schedule term_wait { IEC104::cmd_timer(key, T) };
        return;
        }

    if ( cot == 10 )
        {
        ci$terminated = T;
        ci$term_delay = now - ci$ts;
        if ( ctx$negative )
            {
            ci$result = "rejected";
            ci$reject_cause = "negative ActTerm";
            }
        else
            ci$result = "terminated";
        cmd_finish(key);
        return;
        }

    # COT 44-47
    ci$confirmed = T;
    ci$confirm_delay = now - ci$ts;
    ci$result = "rejected";
    ci$reject_cause = cot_desc(cot);
    cmd_finish(key);
    }

## Count objects an outstation returns for an open interrogation.
function cmd_count_interrogated(c: connection, ctx: ApduCtx)
    {
    local req_type: count;

    if ( ctx$cot >= 20 && ctx$cot <= 36 )
        req_type = 100;
    else if ( ctx$cot >= 37 && ctx$cot <= 41 )
        req_type = 101;
    else
        return;

    local key: string = oldest_open(cmd_key(c$uid, ctx$common, req_type, 0, "Act"),
                                    ctx$is_orig, "confirmed");

    if ( key != "" )
        ++pending[key]$resp_objects;
    }

## Route one information object into the transaction tracker.
function cmd_observe(c: connection, ctx: ApduCtx, ioa: count, value: string)
    {
    if ( ! log_iec104_cmd )
        return;

    local cot: count = ctx$cot;

    if ( cot == 6 || cot == 8 )
        cmd_request(c, ctx, ioa, value);
    else if ( cot == 7 || cot == 9 || cot == 10 || (cot >= 44 && cot <= 47) )
        cmd_response(c, ctx, ioa);
    else if ( cot >= 20 && cot <= 41 )
        cmd_count_interrogated(c, ctx);
    }

event cmd_timer(key: string, term_stage: bool)
    {
    if ( key !in pending )
        return;   # already written

    if ( ! term_stage )
        {
        # Confirmation timer: only act if nothing confirmed the request.
        if ( ! pending[key]$confirmed )
            cmd_finish(key);   # result stays "no_response"
        return;
        }

    # Confirmed, but no ActTerm within the wait: result stays "confirmed".
    cmd_finish(key);
    }

## ---------------- Per-frame / per-object logging ----------------

## Logs one U-frame or S-frame event (no ASDU involved).
function log_ctrl_frame(c: connection, is_orig: bool, apdu_type: string, note: string)
    {
    local info = base_info(c);
    info$apdu_dir = dir_str(is_orig);
    info$apdu_type = apdu_type;
    info$note = note;
    Log::write(IEC104::LOG, info);
    }

## Fills the per-APDU fields of an I-frame row.
function apdu_info(c: connection, ctx: ApduCtx): Info
    {
    local info = base_info(c);
    info$apdu_dir = ctx$dir;
    info$apdu_type = "I";
    info$ns = ctx$ns;
    info$nr = ctx$nr;
    info$typeid = ctx$typeid;
    info$type_desc = typeid_desc(ctx$typeid);
    info$cot = ctx$cot;
    info$cot_desc = cot_desc(ctx$cot);
    info$negative = ctx$negative;
    info$common_addr = ctx$common;
    info$num_obj = ctx$num_obj;
    info$sq = ctx$sq;
    return info;
    }

## Logs one summary row for an ASDU whose TypeID isn't in value_len_table
## (unrecognized/unimplemented) -- raw hex only, no per-object decode.
function log_unrecognized_asdu(c: connection, ctx: ApduCtx, asdu: string)
    {
    local vhex: string = bytestring_to_hexstr(asdu);
    local info = apdu_info(c, ctx);

    info$value_hex = vhex;
    info$note = fmt("%s COT=%d (%s) num_obj=%d sq=%s (unrecognized TypeID, raw ASDU=0x%s)",
                    info$type_desc, ctx$cot, info$cot_desc, ctx$num_obj, ctx$sq, vhex);

    if ( log_iec104 )
        Log::write(IEC104::LOG, info);

    # Still track requests/replies of unrecognized types (for example an
    # unknown TypeID rejected with COT 44), keyed on the first IOA.
    local ioa: count = 0;
    local value: string = "";
    if ( |asdu| >= 9 )
        ioa = get_le24(asdu, 7);
    if ( |asdu| > 9 )
        value = sub_bytes(asdu, 10, |asdu| - 9);

    cmd_observe(c, ctx, ioa, value);
    }

## Logs one decoded information object (one IOA + its value) for a
## recognized TypeID. Handles the "boolean-style" (spi) and "CP56-tagged"
## (clock) cases explicitly; everything else still gets value_hex + note.
function log_object(c: connection, ctx: ApduCtx, ioa: count, value: string)
    {
    local typeid: count = ctx$typeid;
    local cot: count = ctx$cot;
    local info = apdu_info(c, ctx);
    local vhex: string = bytestring_to_hexstr(value);
    local extra: string = "";

    info$ioa = ioa;
    info$ioa_desc = ioa_desc(ioa);
    info$value_hex = vhex;

    ## -- value-aware protection-setpoint detection (Lab 3D) --
    ## A C_SE_NC_1 (TypeID 50) activation (COT 6) write to a protection
    ## setpoint IOA (501-504) should never happen on this class of device.
    ## Raise a Notice for the write, and a second Notice if a 51P pickup
    ## (IOA 501) is driven below the target RTU's legitimate floor.
    if ( typeid == 50 && cot == 6 && ioa >= 501 && ioa <= 504 && |value| >= 4 )
        {
        local raw: count = get_le32(value, 1);

        NOTICE([$note=Protection_Setpoint_Write, $conn=c,
                $msg=fmt("C_SE_NC_1 write to protection setpoint IOA %d (%s), raw=0x%x",
                         ioa, ioa_desc(ioa), raw),
                $identifier=cat(c$id$resp_h, ioa)]);

        if ( ioa == 501 && c$id$resp_h in pickup_floor_bits
             && raw < pickup_floor_bits[c$id$resp_h] )
            NOTICE([$note=Protection_Setpoint_Below_Floor, $conn=c,
                    $msg=fmt("51P pickup on %s set below legitimate floor (raw=0x%x < 0x%x)",
                             c$id$resp_h, raw, pickup_floor_bits[c$id$resp_h]),
                    $identifier=cat(c$id$resp_h, "501-floor")]);
        }

    ## -- boolean-style single-bit/two-bit points and commands --
    if ( typeid == 1 || typeid == 30 || typeid == 45 )
        {
        info$spi_val = get_byte(value, 1) & 0x01;
        info$spi_desc = info$spi_val == 1 ? "On" : "Off";
        }
    else if ( typeid == 3 || typeid == 31 || typeid == 46 )
        {
        info$spi_val = get_byte(value, 1) & 0x03;
        if ( info$spi_val == 1 )
            info$spi_desc = "Off";
        else if ( info$spi_val == 2 )
            info$spi_desc = "On";
        else
            info$spi_desc = "Indeterminate";
        }
    else if ( typeid == 47 )
        {
        info$spi_val = get_byte(value, 1) & 0x03;
        if ( info$spi_val == 1 )
            info$spi_desc = "Lower";
        else if ( info$spi_val == 2 )
            info$spi_desc = "Higher";
        else
            info$spi_desc = "Indeterminate";
        }

    ## -- CP56Time2a-carrying types --
    if ( typeid == 103 || typeid == 104 )
        info$clock_ts = decode_cp56time2a(value, 1);
    else if ( typeid == 30 || typeid == 31 )
        info$clock_ts = decode_cp56time2a(value, 2);   # 1-byte SIQ/DIQ then CP56
    else if ( typeid == 32 )
        info$clock_ts = decode_cp56time2a(value, 3);   # VTI+QDS(2) then CP56
    else if ( typeid == 33 )
        info$clock_ts = decode_cp56time2a(value, 6);   # BSI+QDS(5) then CP56
    else if ( typeid == 34 || typeid == 35 )
        info$clock_ts = decode_cp56time2a(value, 4);   # value+QDS(3) then CP56
    else if ( typeid == 36 )
        info$clock_ts = decode_cp56time2a(value, 6);   # value+QDS(5) then CP56

    if ( typeid == 100 )
        extra = fmt(" QOI=%d", get_byte(value, 1));

    if ( info?$spi_val && info?$clock_ts )
        info$note = fmt("%s IOA=%d (%s) COT=%d (%s)%s value=0x%s ts=%s",
                        info$type_desc, ioa, info$ioa_desc, cot, info$cot_desc,
                        extra, vhex, info$clock_ts);
    else
        info$note = fmt("%s IOA=%d (%s) COT=%d (%s)%s value=0x%s",
                        info$type_desc, ioa, info$ioa_desc, cot, info$cot_desc,
                        extra, vhex);

    if ( log_iec104 )
        Log::write(IEC104::LOG, info);

    cmd_observe(c, ctx, ioa, value);
    }

## Walks every information object in a (possibly multi-object) ASDU and logs
## each one. Handles SQ=0 (each object has its own IOA) and SQ=1 (sequential:
## one base IOA, then num_obj values back-to-back, IOA = base+i).
function walk_asdu_objects(c: connection, ctx: ApduCtx, asdu: string)
    {
    local asdu_len: count = |asdu|;
    local value_len: count = value_len_table[ctx$typeid];
    local cur: count = 7;   # first byte after TypeID/VSQ/COT/CommonAddr (1-based)
    local i: count = 0;
    local base_ioa: count;
    local this_ioa: count;
    local value: string;

    if ( ctx$sq )
        {
        if ( cur + 2 > asdu_len )
            return;  # truncated: not even a base IOA present
        base_ioa = get_le24(asdu, cur);
        cur = cur + 3;

        while ( i < ctx$num_obj )
            {
            if ( cur + value_len - 1 > asdu_len )
                break;  # truncated -- stop rather than read garbage
            value = sub_bytes(asdu, cur, value_len);
            this_ioa = base_ioa + i;
            log_object(c, ctx, this_ioa, value);
            cur = cur + value_len;
            i = i + 1;
            }
        }
    else
        {
        while ( i < ctx$num_obj )
            {
            if ( cur + 2 > asdu_len )
                break;
            this_ioa = get_le24(asdu, cur);
            cur = cur + 3;
            if ( cur + value_len - 1 > asdu_len )
                break;
            value = sub_bytes(asdu, cur, value_len);
            log_object(c, ctx, this_ioa, value);
            cur = cur + value_len;
            i = i + 1;
            }
        }
    }

## ---------------- APDU parsing ----------------

## Handles one complete APDU (0x68, length, 4 control bytes, optional ASDU).
function handle_apdu(c: connection, is_orig: bool, apdu: string)
    {
    local apdu_len: count = |apdu| - 2;
    local cf1: count = get_byte(apdu, 3);
    local cf2: count = get_byte(apdu, 4);
    local cf3: count = get_byte(apdu, 5);
    local cf4: count = get_byte(apdu, 6);
    local dir: string = dir_str(is_orig);

    ## U-frame
    if ( (cf1 & 0x03) == 0x03 )
        {
        if ( ! log_iec104 )
            return;

        if ( cf1 == 0x07 )
            log_ctrl_frame(c, is_orig, "U", "STARTDT.ACT");
        else if ( cf1 == 0x0b )
            log_ctrl_frame(c, is_orig, "U", "STARTDT.CON");
        else if ( cf1 == 0x13 )
            log_ctrl_frame(c, is_orig, "U", "STOPDT.ACT");
        else if ( cf1 == 0x23 )
            log_ctrl_frame(c, is_orig, "U", "STOPDT.CON");
        else if ( cf1 == 0x43 )
            log_ctrl_frame(c, is_orig, "U", "TESTFR.ACT");
        else if ( cf1 == 0x83 )
            log_ctrl_frame(c, is_orig, "U", "TESTFR.CON");
        else
            log_ctrl_frame(c, is_orig, "U", fmt("Unknown U-frame CF1=0x%02x", cf1));
        return;
        }

    local nr: count = ((cf4 << 8) | cf3) >> 1;

    ## S-frame
    if ( (cf1 & 0x03) == 0x01 )
        {
        if ( ! log_iec104 )
            return;

        local sinfo = base_info(c);
        sinfo$apdu_dir = dir;
        sinfo$apdu_type = "S";
        sinfo$nr = nr;
        sinfo$note = fmt("S-frame ack rseq=%d", nr);
        Log::write(IEC104::LOG, sinfo);
        return;
        }

    ## I-frame
    local ns: count = ((cf2 << 8) | cf1) >> 1;

    if ( check_sequence )
        {
        local dk: string = dir_key(c, is_orig);
        if ( dk in next_ns && next_ns[dk] != ns )
            NOTICE([$note=Sequence_Discontinuity, $conn=c,
                    $msg=fmt("IEC-104 N(S) discontinuity (%s): expected %d, saw %d",
                             dir, next_ns[dk], ns),
                    $identifier=dk]);
        next_ns[dk] = (ns + 1) % 32768;
        }

    if ( apdu_len < 10 )
        return;   # I-frame too short to carry an ASDU header

    local asdu: string = sub_bytes(apdu, 7, apdu_len - 4);
    local cot_lo: count = get_byte(asdu, 3);
    local vsq: count = get_byte(asdu, 2);

    local ctx = ApduCtx($is_orig=is_orig, $dir=dir, $ns=ns, $nr=nr,
                        $typeid=get_byte(asdu, 1),
                        $cot=cot_lo & 0x3f,
                        $negative=(cot_lo & 0x40) != 0,
                        $common=get_le16(asdu, 5),
                        $num_obj=vsq & 0x7f,
                        $sq=(vsq & 0x80) != 0);

    if ( ctx$num_obj > 0 && ctx$typeid in value_len_table )
        walk_asdu_objects(c, ctx, asdu);
    else if ( ctx$num_obj > 0 )
        log_unrecognized_asdu(c, ctx, asdu);
    }

## ---------------- Stream-level hooks ----------------

## Reassembled, in-order stream data for one direction. Bytes are buffered
## until a whole APDU is available; any partial APDU at the end of a
## delivery waits for the next one.
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    if ( ! is_iec104(c) )
        return;

    local k: string = dir_key(c, is_orig);
    local data: string = contents;

    if ( k in rx_buf )
        data = rx_buf[k] + contents;

    local n: count = |data|;
    local pos: count = 1;
    local len: count;

    while ( pos <= n )
        {
        if ( get_byte(data, pos) != 0x68 )
            {
            ++pos;   # resynchronize on the next start byte
            next;
            }

        if ( pos + 1 > n )
            break;   # need the length byte

        len = get_byte(data, pos + 1);
        if ( len < 4 )
            {
            ++pos;   # not a valid APDU length
            next;
            }

        if ( pos + 1 + len > n )
            break;   # incomplete APDU: wait for more data

        handle_apdu(c, is_orig, sub_bytes(data, pos, 2 + len));
        pos = pos + 2 + len;
        }

    if ( pos <= n )
        rx_buf[k] = sub_bytes(data, pos, n - pos + 1);
    else if ( k in rx_buf )
        delete rx_buf[k];
    }

## Missing bytes (capture loss): drop the partial APDU and re-baseline the
## sequence check instead of reporting a false discontinuity.
event content_gap(c: connection, is_orig: bool, seq: count, length: count)
    {
    if ( ! is_iec104(c) )
        return;

    local k: string = dir_key(c, is_orig);
    delete rx_buf[k];
    delete next_ns[k];
    }

event connection_state_remove(c: connection)
    {
    if ( ! is_iec104(c) )
        return;

    delete rx_buf[dir_key(c, T)];
    delete rx_buf[dir_key(c, F)];
    delete next_ns[dir_key(c, T)];
    delete next_ns[dir_key(c, F)];

    if ( |pending| == 0 )
        return;

    # Session over: write every transaction still open on it.
    cmd_flush(c$uid);
    }

event zeek_done()
    {
    cmd_flush("");
    }