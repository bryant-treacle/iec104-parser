## File: iec_104.zeek
## IEC 60870-5-104 parser using packet_contents.
##
## COURSE-CORRECTED EDITION. Changes from the originally distributed script:
##   1. ioa_names now reflects the lab RTU point map (Chapter 2 / Lab 3A Task 2)
##      instead of the placeholder "Feeder A-F Breaker" labels.
##   2. Adds value-aware protection-setpoint Notices (Chapter 3, Lab 3D): an
##      IEC104::Protection_Setpoint_Write for any C_SE_NC_1 write to IOA 501-504,
##      and an IEC104::Protection_Setpoint_Below_Floor when a 51P pickup (IOA 501)
##      is written below the target RTU's legitimate floor. The floors are keyed
##      by RTU IP in pickup_floor_bits below -- edit that table for your own
##      addressing before deploying outside the lab.
##
## v2 (retained from original): covers all common monitoring TypeIDs
## (1,3,5,7,9,11,13) and their CP56-tagged counterparts (30-36); all common
## command TypeIDs (45-51), test command (70), interrogation (100), clock sync
## (103); multi-object ASDUs (VSQ count>1, SQ=0 and SQ=1); U-frames and
## S-frames each get a log row; unrecognized TypeIDs get one summary row.
##
## Every object logged carries a raw value_hex field regardless of type, plus
## best-effort semantic decode (spi_val/spi_desc for boolean-style points and
## commands, clock_ts for anything carrying a CP56Time2a) where the format is
## known. Measured/setpoint numeric values (normalized/scaled/short-float) are
## exposed via value_hex; the Lab 3D Notices above decode the short-float
## setpoint value for threshold comparison.
##
## Compatible with older Zeek (no nested local redefs, etc.).

@load base/frameworks/notice

module IEC104;

export {
    const log_iec104 = T &redef;

    redef enum Log::ID += { LOG };

    ## Value-aware protection-setpoint notices (Lab 3D).
    redef enum Notice::Type += {
        Protection_Setpoint_Write,
        Protection_Setpoint_Below_Floor
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

        apdu_dir:    string &log &optional;  # "orig->resp"
        apdu_type:   string &log &optional;  # "I","S","U","conn"

        typeid:      count  &log &optional;
        type_desc:   string &log &optional;

        cot:         count  &log &optional;  # Cause of transmission
        cot_desc:    string &log &optional;

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
    if ( t == 70 )  return "M_EI_NA_1 end of initialization";
    if ( t == 100 ) return "C_IC_NA_1 interrogation command";
    if ( t == 103 ) return "C_CS_NA_1 clock sync";
    if ( t == 104 ) return "C_TS_TA_1 test command";

    return fmt("TypeID 0x%02x (unrecognized)", t);
    }

function cot_desc(c: count): string
    {
    if ( c == 3 )  return "Spont";
    if ( c == 6 )  return "Act";
    if ( c == 7 )  return "ActCon";
    if ( c == 10 ) return "Term";
    if ( c == 20 ) return "Inrogen";
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

## ---------------- Logging setup ----------------

event zeek_init()
    {
    if ( log_iec104 )
        Log::create_stream(IEC104::LOG, [$columns=Info, $path="iec104"]);
    }

event connection_established(c: connection)
    {
    if ( ! log_iec104 )
        return;

    if ( c$id$orig_p != 2404/tcp && c$id$resp_p != 2404/tcp )
        return;

    Log::write(IEC104::LOG, Info(
        $ts=network_time(),
        $uid=c$uid,
        $id_orig_h=c$id$orig_h,
        $id_orig_p=c$id$orig_p,
        $id_resp_h=c$id$resp_h,
        $id_resp_p=c$id$resp_p,
        $apdu_type= "conn",
        $typeid=0,
        $type_desc="IEC104 connection",
        $note="IEC104 connection established"
    ));
    }

## ---------------- Per-frame / per-object logging ----------------

## Logs one U-frame or S-frame event (no ASDU involved).
function log_ctrl_frame(c: connection, apdu_type: string, note: string)
    {
    Log::write(IEC104::LOG, Info(
        $ts=network_time(),
        $uid=c$uid,
        $id_orig_h=c$id$orig_h,
        $id_orig_p=c$id$orig_p,
        $id_resp_h=c$id$resp_h,
        $id_resp_p=c$id$resp_p,
        $apdu_dir="orig->resp",
        $apdu_type=apdu_type,
        $note=note
    ));
    }

## Logs one summary row for an ASDU whose TypeID isn't in value_len_table
## (unrecognized/unimplemented) -- raw hex only, no per-object decode.
function log_unrecognized_asdu(c: connection, typeid: count, cot: count, common: count,
                                num_obj: count, sq: bool, asdu: string)
    {
    local tdesc: string = typeid_desc(typeid);
    local cdesc: string = cot_desc(cot);
    local vhex: string = bytestring_to_hexstr(asdu);
    local note: string = fmt("%s COT=%d (%s) num_obj=%d sq=%s (unrecognized TypeID, raw ASDU=0x%s)",
                              tdesc, cot, cdesc, num_obj, sq, vhex);

    Log::write(IEC104::LOG, Info(
        $ts=network_time(),
        $uid=c$uid,
        $id_orig_h=c$id$orig_h,
        $id_orig_p=c$id$orig_p,
        $id_resp_h=c$id$resp_h,
        $id_resp_p=c$id$resp_p,
        $apdu_dir="orig->resp",
        $apdu_type="I",
        $typeid=typeid,
        $type_desc=tdesc,
        $cot=cot,
        $cot_desc=cdesc,
        $common_addr=common,
        $num_obj=num_obj,
        $sq=sq,
        $value_hex=vhex,
        $note=note
    ));
    }

## Logs one decoded information object (one IOA + its value) for a
## recognized TypeID. Handles the "boolean-style" (spi) and "CP56-tagged"
## (clock) cases explicitly; everything else still gets value_hex + note.
function log_object(c: connection, typeid: count, cot: count, common: count,
                     ioa: count, num_obj: count, sq: bool, value: string)
    {
    local tdesc: string = typeid_desc(typeid);
    local cdesc: string = cot_desc(cot);
    local idesc: string = ioa_desc(ioa);
    local vhex: string  = bytestring_to_hexstr(value);

    local spi_val: count;
    local spi_desc: string;
    local clock_ts: string;
    local have_spi: bool = F;
    local have_clock: bool = F;
    local extra: string = "";
    local note: string;

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
        spi_val = get_byte(value, 1) & 0x01;
        spi_desc = spi_val == 1 ? "On" : "Off";
        have_spi = T;
        }
    else if ( typeid == 3 || typeid == 31 || typeid == 46 )
        {
        spi_val = get_byte(value, 1) & 0x03;
        if ( spi_val == 1 )
            spi_desc = "Off";
        else if ( spi_val == 2 )
            spi_desc = "On";
        else
            spi_desc = "Indeterminate";
        have_spi = T;
        }
    else if ( typeid == 47 )
        {
        spi_val = get_byte(value, 1) & 0x03;
        if ( spi_val == 1 )
            spi_desc = "Lower";
        else if ( spi_val == 2 )
            spi_desc = "Higher";
        else
            spi_desc = "Indeterminate";
        have_spi = T;
        }

    ## -- CP56Time2a-carrying types --
    if ( typeid == 103 || typeid == 104 )
        {
        clock_ts = decode_cp56time2a(value, 1);
        have_clock = T;
        }
    else if ( typeid == 30 || typeid == 31 )
        {
        clock_ts = decode_cp56time2a(value, 2);   # 1-byte SIQ/DIQ then CP56
        have_clock = T;
        }
    else if ( typeid == 32 )
        {
        clock_ts = decode_cp56time2a(value, 3);   # VTI+QDS(2) then CP56
        have_clock = T;
        }
    else if ( typeid == 33 )
        {
        clock_ts = decode_cp56time2a(value, 6);   # BSI+QDS(5) then CP56
        have_clock = T;
        }
    else if ( typeid == 34 || typeid == 35 )
        {
        clock_ts = decode_cp56time2a(value, 4);   # value+QDS(3) then CP56
        have_clock = T;
        }
    else if ( typeid == 36 )
        {
        clock_ts = decode_cp56time2a(value, 6);   # value+QDS(5) then CP56
        have_clock = T;
        }

    if ( typeid == 100 )
        extra = fmt(" QOI=%d", get_byte(value, 1));

    if ( have_spi && have_clock )
        note = fmt("%s IOA=%d (%s) COT=%d (%s)%s value=0x%s ts=%s",
                   tdesc, ioa, idesc, cot, cdesc, extra, vhex, clock_ts);
    else
        note = fmt("%s IOA=%d (%s) COT=%d (%s)%s value=0x%s",
                   tdesc, ioa, idesc, cot, cdesc, extra, vhex);

    if ( have_spi && have_clock )
        Log::write(IEC104::LOG, Info(
            $ts=network_time(), $uid=c$uid,
            $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
            $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p,
            $apdu_dir="orig->resp", $apdu_type="I",
            $typeid=typeid, $type_desc=tdesc,
            $cot=cot, $cot_desc=cdesc,
            $common_addr=common, $ioa=ioa, $ioa_desc=idesc,
            $num_obj=num_obj, $sq=sq,
            $spi_val=spi_val, $spi_desc=spi_desc,
            $clock_ts=clock_ts, $value_hex=vhex, $note=note
        ));
    else if ( have_spi )
        Log::write(IEC104::LOG, Info(
            $ts=network_time(), $uid=c$uid,
            $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
            $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p,
            $apdu_dir="orig->resp", $apdu_type="I",
            $typeid=typeid, $type_desc=tdesc,
            $cot=cot, $cot_desc=cdesc,
            $common_addr=common, $ioa=ioa, $ioa_desc=idesc,
            $num_obj=num_obj, $sq=sq,
            $spi_val=spi_val, $spi_desc=spi_desc,
            $value_hex=vhex, $note=note
        ));
    else if ( have_clock )
        Log::write(IEC104::LOG, Info(
            $ts=network_time(), $uid=c$uid,
            $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
            $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p,
            $apdu_dir="orig->resp", $apdu_type="I",
            $typeid=typeid, $type_desc=tdesc,
            $cot=cot, $cot_desc=cdesc,
            $common_addr=common, $ioa=ioa, $ioa_desc=idesc,
            $num_obj=num_obj, $sq=sq,
            $clock_ts=clock_ts, $value_hex=vhex, $note=note
        ));
    else
        Log::write(IEC104::LOG, Info(
            $ts=network_time(), $uid=c$uid,
            $id_orig_h=c$id$orig_h, $id_orig_p=c$id$orig_p,
            $id_resp_h=c$id$resp_h, $id_resp_p=c$id$resp_p,
            $apdu_dir="orig->resp", $apdu_type="I",
            $typeid=typeid, $type_desc=tdesc,
            $cot=cot, $cot_desc=cdesc,
            $common_addr=common, $ioa=ioa, $ioa_desc=idesc,
            $num_obj=num_obj, $sq=sq,
            $value_hex=vhex, $note=note
        ));
    }

## Walks every information object in a (possibly multi-object) ASDU and logs
## each one. Handles SQ=0 (each object has its own IOA) and SQ=1 (sequential:
## one base IOA, then num_obj values back-to-back, IOA = base+i).
function walk_asdu_objects(c: connection, typeid: count, cot: count, common: count,
                            num_obj: count, sq: bool, asdu: string, asdu_len: count)
    {
    local value_len: count = value_len_table[typeid];
    local cur: count = 7;   # first byte after TypeID/VSQ/COT/CommonAddr (1-based)
    local i: count = 0;
    local base_ioa: count;
    local this_ioa: count;
    local value: string;

    if ( sq )
        {
        if ( cur + 2 > asdu_len )
            return;  # truncated: not even a base IOA present
        base_ioa = get_le24(asdu, cur);
        cur = cur + 3;

        while ( i < num_obj )
            {
            if ( cur + value_len - 1 > asdu_len )
                break;  # truncated -- stop rather than read garbage
            value = sub_bytes(asdu, cur, value_len);
            this_ioa = base_ioa + i;
            log_object(c, typeid, cot, common, this_ioa, num_obj, sq, value);
            cur = cur + value_len;
            i = i + 1;
            }
        }
    else
        {
        while ( i < num_obj )
            {
            if ( cur + 2 > asdu_len )
                break;
            this_ioa = get_le24(asdu, cur);
            cur = cur + 3;
            if ( cur + value_len - 1 > asdu_len )
                break;
            value = sub_bytes(asdu, cur, value_len);
            log_object(c, typeid, cot, common, this_ioa, num_obj, sq, value);
            cur = cur + value_len;
            i = i + 1;
            }
        }
    }

## ---------------- APDU parsing ----------------

function parse_apdu(c: connection, data: string, pos: count): count
    {
    local n: count = |data|;

    local start: count;
    local apdu_len: count;
    local total_len: count;
    local cf1: count;
    local cf2: count;
    local cf3: count;
    local cf4: count;
    local apdu_type: string;

    local asdu_start: count;
    local asdu_len: count;
    local asdu: string;

    local typeid: count;
    local vsq: count;
    local cot_lo: count;
    local cot_hi: count;
    local common: count;
    local cause: count;
    local num_obj: count;
    local sq: bool;
    local rseq: count;

    if ( pos + 1 > n )
        return n + 1;

    start = get_byte(data, pos);
    if ( start != 0x68 )
        return pos + 1;

    apdu_len = get_byte(data, pos + 1);
    total_len = 2 + apdu_len;

    if ( pos + total_len - 1 > n )
        return n + 1;

    cf1 = get_byte(data, pos + 2);
    cf2 = get_byte(data, pos + 3);
    cf3 = get_byte(data, pos + 4);
    cf4 = get_byte(data, pos + 5);

    if ( (cf1 & 0x01) == 0x00 )
        apdu_type = "I";
    else if ( (cf1 & 0x03) == 0x01 )
        apdu_type = "S";
    else
        apdu_type = "U";

    if ( apdu_type == "U" )
        {
        if ( cf1 == 0x07 )
            log_ctrl_frame(c, "U", "STARTDT.ACT");
        else if ( cf1 == 0x0b )
            log_ctrl_frame(c, "U", "STARTDT.CON");
        else if ( cf1 == 0x13 )
            log_ctrl_frame(c, "U", "STOPDT.ACT");
        else if ( cf1 == 0x23 )
            log_ctrl_frame(c, "U", "STOPDT.CON");
        else if ( cf1 == 0x43 )
            log_ctrl_frame(c, "U", "TESTFR.ACT");
        else if ( cf1 == 0x83 )
            log_ctrl_frame(c, "U", "TESTFR.CON");
        else
            log_ctrl_frame(c, "U", fmt("Unknown U-frame CF1=0x%02x", cf1));

        return pos + total_len;
        }

    if ( apdu_type == "S" )
        {
        rseq = ((cf4 << 8) | cf3) >> 1;
        log_ctrl_frame(c, "S", fmt("S-frame ack rseq=%d", rseq));
        return pos + total_len;
        }

    ## apdu_type == "I"
    if ( apdu_len >= 4 )
        {
        asdu_start = pos + 6;
        asdu_len   = apdu_len - 4;

        if ( asdu_len >= 6 && asdu_start + asdu_len - 1 <= n )
            {
            asdu = sub_bytes(data, asdu_start, asdu_len);

            typeid = get_byte(asdu, 1);
            vsq    = get_byte(asdu, 2);
            cot_lo = get_byte(asdu, 3);
            cot_hi = get_byte(asdu, 4);
            common = get_le16(asdu, 5);
            cause  = cot_lo & 0x3f;

            num_obj = vsq & 0x7f;
            sq      = (vsq & 0x80) != 0;

            if ( num_obj > 0 && typeid in value_len_table )
                walk_asdu_objects(c, typeid, cause, common, num_obj, sq, asdu, asdu_len);
            else if ( num_obj > 0 )
                log_unrecognized_asdu(c, typeid, cause, common, num_obj, sq, asdu);
            }
        }

    return pos + total_len;
    }

## ---------------- Packet-level hook ----------------

event packet_contents(c: connection, contents: string)
    {
    if ( ! log_iec104 )
        return;

    if ( c$id$orig_p != 2404/tcp && c$id$resp_p != 2404/tcp )
        return;

    local n: count = |contents|;
    if ( n < 6 )
        return;

    local pos: count = 1;

    while ( pos + 1 <= n )
        {
        if ( get_byte(contents, pos) != 0x68 )
            {
            ++pos;
            }

        pos = parse_apdu(c, contents, pos);
        }
    }
