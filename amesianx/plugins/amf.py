"""AMF plugin: AMF binary <-> JSON transformation for Adobe Flex/BlazeDS.

Can also be run as a standalone CLI tool:
  python -m amesianx.plugins.amf <file> --list
  python -m amesianx.plugins.amf <file> --list --search "keyword"
  python -m amesianx.plugins.amf <file> --list --deep --limit 100
  python -m amesianx.plugins.amf <file> --json
"""

import json
import struct
import base64
import traceback
import os
import time

try:
    from .base import BodyTransformPlugin
except (ImportError, SystemError):
    # Running as standalone CLI — define a stub
    class BodyTransformPlugin:
        name = "BasePlugin"
        def should_transform_inbound(self, body, headers): return False
        def transform_inbound(self, body, headers): return body, {}
        def should_transform_outbound(self, body, headers): return False
        def transform_outbound(self, body, headers): return body, {}
        def should_transform_response(self, body, headers): return False
        def transform_response_decode(self, body, headers): return body, {}
        def transform_response_encode(self, body, headers): return body, {}


# --- AMF0 type markers ---
AMF0_NUMBER      = 0x00
AMF0_BOOLEAN     = 0x01
AMF0_STRING      = 0x02
AMF0_OBJECT      = 0x03
AMF0_NULL        = 0x05
AMF0_UNDEFINED   = 0x06
AMF0_REFERENCE   = 0x07
AMF0_ECMA_ARRAY  = 0x08
AMF0_OBJ_END     = 0x09
AMF0_STRICT_ARRAY = 0x0A
AMF0_DATE        = 0x0B
AMF0_LONG_STRING = 0x0C
AMF0_XML         = 0x0F
AMF0_TYPED_OBJ   = 0x10
AMF0_AMF3        = 0x11

# --- AMF3 type markers ---
AMF3_UNDEFINED   = 0x00
AMF3_NULL        = 0x01
AMF3_FALSE       = 0x02
AMF3_TRUE        = 0x03
AMF3_INTEGER     = 0x04
AMF3_DOUBLE      = 0x05
AMF3_STRING      = 0x06
AMF3_XML_DOC     = 0x07
AMF3_DATE        = 0x08
AMF3_ARRAY       = 0x09
AMF3_OBJECT      = 0x0A
AMF3_XML         = 0x0B
AMF3_BYTEARRAY   = 0x0C


# BlazeDS message classes that use readExternal/writeExternal
# Includes compact aliases (DSK, DSC, etc.)
BLAZEDS_MESSAGE_CLASSES = {
    "flex.messaging.messages.AcknowledgeMessage",
    "flex.messaging.messages.AcknowledgeMessageExt",
    "flex.messaging.messages.CommandMessage",
    "flex.messaging.messages.CommandMessageExt",
    "flex.messaging.messages.RemotingMessage",
    "flex.messaging.messages.AsyncMessage",
    "flex.messaging.messages.AsyncMessageExt",
    "flex.messaging.messages.ErrorMessage",
    "DSK",  # compact AcknowledgeMessage
    "DSC",  # compact CommandMessage
    "DSA",  # compact AsyncMessage
}

# AbstractMessage flag bits (first flag byte group)
_AM_BODY            = 0x01
_AM_CLIENT_ID       = 0x02
_AM_DESTINATION     = 0x04
_AM_HEADERS         = 0x08
_AM_MESSAGE_ID      = 0x10
_AM_TIMESTAMP       = 0x20
_AM_TIME_TO_LIVE    = 0x40
_AM_HAS_NEXT        = 0x80
# AbstractMessage second flag byte
_AM_CLIENT_ID_BYTES = 0x01
_AM_MSG_ID_BYTES    = 0x02

# AsyncMessage flag bits
_ASYNC_CORRELATION_ID       = 0x01
_ASYNC_CORRELATION_ID_BYTES = 0x02

# CommandMessage flag bits
_CMD_OPERATION = 0x01


class AMFDecoder:
    """Decode AMF binary to Python objects."""

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.amf0_refs = []
        self.string_refs = []
        self.object_refs = []
        self.trait_refs = []

    def remaining(self):
        return len(self.data) - self.pos

    def read_bytes(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("AMF read past end: need %d, have %d" % (n, self.remaining()))
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u8(self):
        return self.read_bytes(1)[0]

    def read_u16(self):
        return struct.unpack('>H', self.read_bytes(2))[0]

    def read_u32(self):
        return struct.unpack('>I', self.read_bytes(4))[0]

    def read_i32(self):
        return struct.unpack('>i', self.read_bytes(4))[0]

    def read_double(self):
        return struct.unpack('>d', self.read_bytes(8))[0]

    # --- AMF0 ---

    def read_amf0_utf8(self):
        length = self.read_u16()
        return self.read_bytes(length).decode('utf-8', errors='replace')

    def read_amf0_long_utf8(self):
        length = self.read_u32()
        return self.read_bytes(length).decode('utf-8', errors='replace')

    def read_amf0_value(self):
        marker = self.read_u8()

        if marker == AMF0_NUMBER:
            return self.read_double()

        elif marker == AMF0_BOOLEAN:
            return self.read_u8() != 0

        elif marker == AMF0_STRING:
            return self.read_amf0_utf8()

        elif marker == AMF0_OBJECT:
            obj = {"__amf_type": "amf0_object"}
            self.amf0_refs.append(obj)
            while True:
                key = self.read_amf0_utf8()
                if self.pos < len(self.data) and self.data[self.pos] == AMF0_OBJ_END:
                    self.pos += 1
                    break
                if not key and self.pos >= len(self.data):
                    break
                obj[key] = self.read_amf0_value()
            return obj

        elif marker == AMF0_NULL:
            return None

        elif marker == AMF0_UNDEFINED:
            return {"__amf_type": "undefined"}

        elif marker == AMF0_REFERENCE:
            ref = self.read_u16()
            return {"__amf_type": "amf0_ref", "index": ref}

        elif marker == AMF0_ECMA_ARRAY:
            count = self.read_u32()
            obj = {"__amf_type": "amf0_ecma_array"}
            self.amf0_refs.append(obj)
            while True:
                key = self.read_amf0_utf8()
                if self.pos < len(self.data) and self.data[self.pos] == AMF0_OBJ_END:
                    self.pos += 1
                    break
                if not key and self.pos >= len(self.data):
                    break
                obj[key] = self.read_amf0_value()
            return obj

        elif marker == AMF0_STRICT_ARRAY:
            count = self.read_u32()
            arr = []
            self.amf0_refs.append(arr)
            for _ in range(count):
                arr.append(self.read_amf0_value())
            return arr

        elif marker == AMF0_DATE:
            ms = self.read_double()
            tz = struct.unpack('>h', self.read_bytes(2))[0]
            return {"__amf_type": "amf0_date", "ms": ms, "tz": tz}

        elif marker == AMF0_LONG_STRING:
            return self.read_amf0_long_utf8()

        elif marker == AMF0_XML:
            return {"__amf_type": "amf0_xml", "value": self.read_amf0_long_utf8()}

        elif marker == AMF0_TYPED_OBJ:
            class_name = self.read_amf0_utf8()
            obj = {"__amf_type": "amf0_typed", "__class": class_name}
            self.amf0_refs.append(obj)
            while True:
                key = self.read_amf0_utf8()
                if self.pos < len(self.data) and self.data[self.pos] == AMF0_OBJ_END:
                    self.pos += 1
                    break
                if not key and self.pos >= len(self.data):
                    break
                obj[key] = self.read_amf0_value()
            return obj

        elif marker == AMF0_AMF3:
            return self.read_amf3_value()

        else:
            raw = self.data[self.pos:]
            self.pos = len(self.data)
            return {"__amf_type": "amf0_unknown", "marker": marker,
                    "raw_b64": base64.b64encode(raw).decode()}

    # --- AMF3 ---

    def read_amf3_u29(self):
        n = 0
        for i in range(3):
            b = self.read_u8()
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                return n
        b = self.read_u8()
        n = (n << 8) | b
        return n

    def read_amf3_string(self):
        ref = self.read_amf3_u29()
        if (ref & 1) == 0:
            idx = ref >> 1
            if idx < len(self.string_refs):
                return self.string_refs[idx]
            return ""
        length = ref >> 1
        if length == 0:
            return ""
        s = self.read_bytes(length).decode('utf-8', errors='replace')
        self.string_refs.append(s)
        return s

    def read_amf3_value(self):
        marker = self.read_u8()

        if marker == AMF3_UNDEFINED:
            return {"__amf_type": "undefined"}

        elif marker == AMF3_NULL:
            return None

        elif marker == AMF3_FALSE:
            return False

        elif marker == AMF3_TRUE:
            return True

        elif marker == AMF3_INTEGER:
            n = self.read_amf3_u29()
            if n & 0x10000000:
                n -= 0x20000000
            return n

        elif marker == AMF3_DOUBLE:
            return self.read_double()

        elif marker == AMF3_STRING:
            return self.read_amf3_string()

        elif marker in (AMF3_XML_DOC, AMF3_XML):
            ref = self.read_amf3_u29()
            if (ref & 1) == 0:
                idx = ref >> 1
                if idx < len(self.object_refs):
                    return self.object_refs[idx]
                return {"__amf_type": "xml_ref", "index": idx}
            length = ref >> 1
            xml_str = self.read_bytes(length).decode('utf-8', errors='replace')
            result = {"__amf_type": "xml", "value": xml_str}
            self.object_refs.append(result)
            return result

        elif marker == AMF3_DATE:
            ref = self.read_amf3_u29()
            if (ref & 1) == 0:
                idx = ref >> 1
                if idx < len(self.object_refs):
                    return self.object_refs[idx]
                return {"__amf_type": "date_ref", "index": idx}
            ms = self.read_double()
            result = {"__amf_type": "date", "ms": ms}
            self.object_refs.append(result)
            return result

        elif marker == AMF3_ARRAY:
            ref = self.read_amf3_u29()
            if (ref & 1) == 0:
                idx = ref >> 1
                if idx < len(self.object_refs):
                    return self.object_refs[idx]
                return {"__amf_type": "array_ref", "index": idx}
            count = ref >> 1
            result = {"__amf_type": "array", "assoc": {}, "dense": []}
            self.object_refs.append(result)
            while True:
                key = self.read_amf3_string()
                if key == "":
                    break
                result["assoc"][key] = self.read_amf3_value()
            for _ in range(count):
                result["dense"].append(self.read_amf3_value())
            if not result["assoc"]:
                return result["dense"]
            return result

        elif marker == AMF3_OBJECT:
            return self._read_amf3_object()

        elif marker == AMF3_BYTEARRAY:
            ref = self.read_amf3_u29()
            if (ref & 1) == 0:
                idx = ref >> 1
                if idx < len(self.object_refs):
                    return self.object_refs[idx]
                return {"__amf_type": "bytearray_ref", "index": idx}
            length = ref >> 1
            raw = self.read_bytes(length)
            result = {"__amf_type": "bytearray", "b64": base64.b64encode(raw).decode()}
            self.object_refs.append(result)
            return result

        else:
            raw = self.data[self.pos:]
            self.pos = len(self.data)
            return {"__amf_type": "amf3_unknown", "marker": marker,
                    "raw_b64": base64.b64encode(raw).decode()}

    def _read_amf3_object(self):
        ref = self.read_amf3_u29()

        if (ref & 1) == 0:
            idx = ref >> 1
            if idx < len(self.object_refs):
                return self.object_refs[idx]
            return {"__amf_type": "object_ref", "index": idx}

        if (ref & 2) == 0:
            trait_idx = ref >> 2
            if trait_idx < len(self.trait_refs):
                traits = self.trait_refs[trait_idx]
            else:
                traits = {"class": "", "externalizable": False, "dynamic": False, "members": []}
        else:
            externalizable = bool(ref & 4)
            dynamic = bool(ref & 8)
            member_count = ref >> 4
            class_name = self.read_amf3_string()
            members = []
            for _ in range(member_count):
                members.append(self.read_amf3_string())
            traits = {
                "class": class_name,
                "externalizable": externalizable,
                "dynamic": dynamic,
                "members": members,
            }
            self.trait_refs.append(traits)

        obj = {"__amf_type": "object", "__class": traits["class"]}
        self.object_refs.append(obj)

        if traits["externalizable"]:
            obj["__externalizable"] = True
            cls = traits["class"]
            if cls in ("flex.messaging.io.ArrayCollection",
                       "flex.messaging.io.ObjectProxy"):
                obj["value"] = self.read_amf3_value()
            elif cls in BLAZEDS_MESSAGE_CLASSES:
                saved_pos = self.pos
                try:
                    self._read_blazeds_message_external(obj, cls)
                except Exception:
                    self.pos = saved_pos
                    raw = self.data[self.pos:]
                    self.pos = len(self.data)
                    for k in list(obj.keys()):
                        if k not in ("__amf_type", "__class", "__externalizable"):
                            del obj[k]
                    obj["__raw_b64"] = base64.b64encode(raw).decode()
                    print("[AMF] BlazeDS parse failed for %s, falling back to raw" % cls)
            else:
                # Unknown externalizable: try reading one inner AMF value
                saved_pos = self.pos
                try:
                    obj["value"] = self.read_amf3_value()
                except Exception:
                    self.pos = saved_pos
                    raw = self.data[self.pos:]
                    self.pos = len(self.data)
                    obj["__raw_b64"] = base64.b64encode(raw).decode()
            return obj

        for member_name in traits["members"]:
            obj[member_name] = self.read_amf3_value()

        if traits["dynamic"]:
            while True:
                key = self.read_amf3_string()
                if key == "":
                    break
                obj[key] = self.read_amf3_value()

        return obj

    def _read_blazeds_flags(self):
        """Read BlazeDS flag bytes (continuation bit = 0x80)."""
        flags_list = []
        while True:
            b = self.read_u8()
            flags_list.append(b)
            if not (b & 0x80):
                break
        return flags_list

    def _read_blazeds_message_external(self, obj, cls):
        """Read BlazeDS AbstractMessage.readExternal() format."""
        flags_list = self._read_blazeds_flags()
        f0 = flags_list[0] if len(flags_list) > 0 else 0
        f1 = flags_list[1] if len(flags_list) > 1 else 0

        is_async = cls in (
            "flex.messaging.messages.AsyncMessage",
            "flex.messaging.messages.AsyncMessageExt",
            "flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage",
            "DSK", "DSA",
        )
        is_ack = cls in (
            "flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage",
            "DSK",
        )
        is_command = cls in (
            "flex.messaging.messages.CommandMessage",
            "flex.messaging.messages.CommandMessageExt",
            "DSC",
        )

        # Find body boundary using tail scanning for large payloads
        tail_start = None
        tail_field_count = 0
        for bit in (_AM_CLIENT_ID, _AM_DESTINATION, _AM_HEADERS, _AM_MESSAGE_ID,
                    _AM_TIMESTAMP, _AM_TIME_TO_LIVE):
            if f0 & bit:
                tail_field_count += 1
        if f1 & _AM_CLIENT_ID_BYTES: tail_field_count += 1
        if f1 & _AM_MSG_ID_BYTES: tail_field_count += 1

        if (f0 & _AM_BODY) and tail_field_count > 0:
            tail_start = self._find_blazeds_tail(f0, f1, is_async, is_ack, is_command, cls)

        if f0 & _AM_BODY:
            if tail_start is not None:
                body_bytes = self.data[self.pos:tail_start]
                body_dec = AMFDecoder(body_bytes)
                body_dec.string_refs = self.string_refs
                body_dec.object_refs = self.object_refs
                body_dec.trait_refs = self.trait_refs
                obj["body"] = body_dec.read_amf3_value()
                self.pos = tail_start
            else:
                obj["body"] = self.read_amf3_value()
        if f0 & _AM_CLIENT_ID:
            obj["clientId"] = self.read_amf3_value()
        if f0 & _AM_DESTINATION:
            obj["destination"] = self.read_amf3_value()
        if f0 & _AM_HEADERS:
            obj["headers"] = self.read_amf3_value()
        if f0 & _AM_MESSAGE_ID:
            obj["messageId"] = self.read_amf3_value()
        if f0 & _AM_TIMESTAMP:
            obj["timestamp"] = self.read_amf3_value()
        if f0 & _AM_TIME_TO_LIVE:
            obj["timeToLive"] = self.read_amf3_value()
        if f1 & _AM_CLIENT_ID_BYTES:
            obj["clientIdBytes"] = self.read_amf3_value()
        if f1 & _AM_MSG_ID_BYTES:
            obj["messageIdBytes"] = self.read_amf3_value()

        if is_async or is_command:
            sub_flags = self._read_blazeds_flags()
            sf0 = sub_flags[0] if len(sub_flags) > 0 else 0
            if is_async:
                if sf0 & _ASYNC_CORRELATION_ID:
                    obj["correlationId"] = self.read_amf3_value()
                if sf0 & _ASYNC_CORRELATION_ID_BYTES:
                    obj["correlationIdBytes"] = self.read_amf3_value()
                if is_ack:
                    ack_flags = self._read_blazeds_flags()
                    if cls == "flex.messaging.messages.ErrorMessage":
                        err_flags = self._read_blazeds_flags()
                        ef0 = err_flags[0] if len(err_flags) > 0 else 0
                        if ef0 & 0x01:
                            obj["extendedData"] = self.read_amf3_value()
                        if ef0 & 0x02:
                            obj["faultCode"] = self.read_amf3_value()
                        if ef0 & 0x04:
                            obj["faultDetail"] = self.read_amf3_value()
                        if ef0 & 0x08:
                            obj["faultString"] = self.read_amf3_value()
                        if ef0 & 0x10:
                            obj["rootCause"] = self.read_amf3_value()
            elif is_command:
                if sf0 & _CMD_OPERATION:
                    obj["operation"] = self.read_amf3_value()

    def _find_blazeds_tail(self, f0, f1, is_async, is_ack, is_command, cls):
        """Find body end by scanning backwards for timestamp (AMF3_DOUBLE)."""
        data = self.data
        total = len(data)

        for tail_size in (200, 500, 2000):
            if tail_size >= total - self.pos:
                continue
            search_start = total - tail_size
            for i in range(search_start, total - 20):
                if data[i] != 0x05:
                    continue
                ts_dec = AMFDecoder(data)
                ts_dec.pos = i
                try:
                    ts_val = ts_dec.read_amf3_value()
                    if not isinstance(ts_val, float) or ts_val < 1600000000000 or ts_val > 2000000000000:
                        continue
                except:
                    continue
                try:
                    if f0 & _AM_TIME_TO_LIVE:
                        ts_dec.read_amf3_value()
                    if f1 & _AM_CLIENT_ID_BYTES:
                        ts_dec.read_amf3_value()
                    if f1 & _AM_MSG_ID_BYTES:
                        ts_dec.read_amf3_value()
                    if is_async or is_command:
                        sf = ts_dec.read_u8()
                        if is_async:
                            if sf & _ASYNC_CORRELATION_ID:
                                ts_dec.read_amf3_value()
                            if sf & _ASYNC_CORRELATION_ID_BYTES:
                                ts_dec.read_amf3_value()
                            if is_ack:
                                ts_dec.read_u8()
                        elif is_command:
                            if sf & _CMD_OPERATION:
                                ts_dec.read_amf3_value()
                    if ts_dec.remaining() == 0:
                        return i
                except:
                    continue
        return None

    # --- Envelope ---

    def read_amf_envelope(self):
        version = self.read_u16()
        header_count = self.read_u16()
        headers = []
        for _ in range(header_count):
            name = self.read_amf0_utf8()
            must_understand = self.read_u8() != 0
            length = self.read_i32()
            value = self.read_amf0_value()
            headers.append({
                "name": name,
                "must_understand": must_understand,
                "value": value,
            })

        body_count = self.read_u16()
        bodies = []
        for _ in range(body_count):
            target = self.read_amf0_utf8()
            response = self.read_amf0_utf8()
            length = self.read_i32()
            self.string_refs = []
            self.object_refs = []
            self.trait_refs = []
            value = self.read_amf0_value()
            bodies.append({
                "target": target,
                "response": response,
                "value": value,
            })

        return {
            "amf_version": version,
            "headers": headers,
            "bodies": bodies,
        }


class AMFEncoder:
    """Encode Python objects (from JSON) back to AMF binary."""

    def __init__(self):
        self.buf = bytearray()
        self.amf0_refs = []
        self.string_table = []
        self.object_table = []
        self.trait_table = []

    def get_bytes(self):
        return bytes(self.buf)

    def write_u8(self, v):
        self.buf.append(v & 0xFF)

    def write_u16(self, v):
        self.buf += struct.pack('>H', v)

    def write_u32(self, v):
        self.buf += struct.pack('>I', v)

    def write_i32(self, v):
        self.buf += struct.pack('>i', v)

    def write_double(self, v):
        self.buf += struct.pack('>d', v)

    def write_amf0_utf8(self, s):
        b = s.encode('utf-8')
        self.write_u16(len(b))
        self.buf += b

    def write_amf0_long_utf8(self, s):
        b = s.encode('utf-8')
        self.write_u32(len(b))
        self.buf += b

    # --- AMF3 ---

    def write_amf3_u29(self, n):
        n = n & 0x1FFFFFFF
        if n < 0x80:
            self.write_u8(n)
        elif n < 0x4000:
            self.write_u8((n >> 7) | 0x80)
            self.write_u8(n & 0x7F)
        elif n < 0x200000:
            self.write_u8((n >> 14) | 0x80)
            self.write_u8((n >> 7) | 0x80)
            self.write_u8(n & 0x7F)
        else:
            self.write_u8((n >> 22) | 0x80)
            self.write_u8((n >> 15) | 0x80)
            self.write_u8((n >> 8) | 0x80)
            self.write_u8(n & 0xFF)

    def write_amf3_string(self, s):
        if s == "":
            self.write_amf3_u29(1)
            return
        if s in self.string_table:
            idx = self.string_table.index(s)
            self.write_amf3_u29(idx << 1)
            return
        self.string_table.append(s)
        b = s.encode('utf-8')
        self.write_amf3_u29((len(b) << 1) | 1)
        self.buf += b

    def write_amf3_value(self, val):
        if val is None:
            self.write_u8(AMF3_NULL)

        elif isinstance(val, bool):
            self.write_u8(AMF3_TRUE if val else AMF3_FALSE)

        elif isinstance(val, int) and not isinstance(val, bool):
            if -0x10000000 <= val <= 0x0FFFFFFF:
                self.write_u8(AMF3_INTEGER)
                self.write_amf3_u29(val & 0x1FFFFFFF)
            else:
                self.write_u8(AMF3_DOUBLE)
                self.write_double(float(val))

        elif isinstance(val, float):
            self.write_u8(AMF3_DOUBLE)
            self.write_double(val)

        elif isinstance(val, str):
            self.write_u8(AMF3_STRING)
            self.write_amf3_string(val)

        elif isinstance(val, list):
            self.write_u8(AMF3_ARRAY)
            self.write_amf3_u29((len(val) << 1) | 1)
            self.write_amf3_string("")
            for item in val:
                self.write_amf3_value(item)

        elif isinstance(val, dict):
            amf_type = val.get("__amf_type", "")

            if amf_type == "undefined":
                self.write_u8(AMF3_UNDEFINED)
            elif amf_type == "date":
                self.write_u8(AMF3_DATE)
                self.write_amf3_u29(1)
                self.write_double(val.get("ms", 0.0))
            elif amf_type == "xml":
                self.write_u8(AMF3_XML)
                xml_bytes = val.get("value", "").encode('utf-8')
                self.write_amf3_u29((len(xml_bytes) << 1) | 1)
                self.buf += xml_bytes
            elif amf_type == "bytearray":
                self.write_u8(AMF3_BYTEARRAY)
                raw = base64.b64decode(val.get("b64", ""))
                self.write_amf3_u29((len(raw) << 1) | 1)
                self.buf += raw
            elif amf_type == "array":
                self.write_u8(AMF3_ARRAY)
                dense = val.get("dense", [])
                assoc = val.get("assoc", {})
                self.write_amf3_u29((len(dense) << 1) | 1)
                for k, v in assoc.items():
                    self.write_amf3_string(k)
                    self.write_amf3_value(v)
                self.write_amf3_string("")
                for item in dense:
                    self.write_amf3_value(item)
            elif amf_type == "object":
                self._write_amf3_object(val)
            elif amf_type in ("amf0_object", "amf0_typed", "amf0_ecma_array"):
                self._write_amf3_object(val)
            elif amf_type == "amf0_date":
                self.write_u8(AMF3_DATE)
                self.write_amf3_u29(1)
                self.write_double(val.get("ms", 0.0))
            elif amf_type == "amf0_xml":
                self.write_u8(AMF3_XML)
                xml_bytes = val.get("value", "").encode('utf-8')
                self.write_amf3_u29((len(xml_bytes) << 1) | 1)
                self.buf += xml_bytes
            else:
                self._write_amf3_object(val)

        else:
            self.write_u8(AMF3_NULL)

    def _write_amf3_object(self, obj):
        self.write_u8(AMF3_OBJECT)

        class_name = obj.get("__class", "")
        is_ext = obj.get("__externalizable", False)

        meta_keys = {"__amf_type", "__class", "__externalizable", "__raw_b64", "value"}
        if is_ext:
            data_keys = []
        else:
            data_keys = [k for k in obj.keys() if k not in meta_keys]

        trait_key = (class_name, is_ext, tuple(data_keys))
        existing = [(t[0], t[1], tuple(t[2])) for t in self.trait_table]
        if trait_key in existing:
            trait_idx = existing.index(trait_key)
            ref = (trait_idx << 2) | 1
            self.write_amf3_u29(ref)
        else:
            self.trait_table.append((class_name, is_ext, data_keys))
            dynamic = not is_ext and not class_name
            member_count = 0 if (is_ext or dynamic) else len(data_keys)
            flags = 3
            if is_ext:
                flags |= 4
            if dynamic:
                flags |= 8
            flags |= (member_count << 4)
            self.write_amf3_u29(flags)
            self.write_amf3_string(class_name)

            if not is_ext and not dynamic:
                for k in data_keys:
                    self.write_amf3_string(k)

        if is_ext:
            if "__raw_b64" in obj:
                self.buf += base64.b64decode(obj["__raw_b64"])
            elif class_name in BLAZEDS_MESSAGE_CLASSES:
                self._write_blazeds_message_external(obj, class_name)
            elif "value" in obj:
                self.write_amf3_value(obj["value"])
            return

        if not class_name:
            for k in data_keys:
                self.write_amf3_string(k)
                self.write_amf3_value(obj[k])
            self.write_amf3_string("")
        else:
            for k in data_keys:
                self.write_amf3_value(obj[k])

    def _write_blazeds_message_external(self, obj, cls):
        """Write BlazeDS AbstractMessage.writeExternal() format."""
        # --- AbstractMessage flags ---
        f0 = 0
        f1 = 0
        if "body" in obj:
            f0 |= _AM_BODY
        if "clientId" in obj:
            f0 |= _AM_CLIENT_ID
        if "destination" in obj:
            f0 |= _AM_DESTINATION
        if "headers" in obj:
            f0 |= _AM_HEADERS
        if "messageId" in obj:
            f0 |= _AM_MESSAGE_ID
        if "timestamp" in obj:
            f0 |= _AM_TIMESTAMP
        if "timeToLive" in obj:
            f0 |= _AM_TIME_TO_LIVE

        if "clientIdBytes" in obj:
            f1 |= _AM_CLIENT_ID_BYTES
        if "messageIdBytes" in obj:
            f1 |= _AM_MSG_ID_BYTES

        if f1:
            f0 |= _AM_HAS_NEXT
        self.write_u8(f0)
        if f1:
            self.write_u8(f1)

        # Write AbstractMessage fields in order
        if f0 & _AM_BODY:
            self.write_amf3_value(obj["body"])
        if f0 & _AM_CLIENT_ID:
            self.write_amf3_value(obj["clientId"])
        if f0 & _AM_DESTINATION:
            self.write_amf3_value(obj["destination"])
        if f0 & _AM_HEADERS:
            self.write_amf3_value(obj["headers"])
        if f0 & _AM_MESSAGE_ID:
            self.write_amf3_value(obj["messageId"])
        if f0 & _AM_TIMESTAMP:
            self.write_amf3_value(obj["timestamp"])
        if f0 & _AM_TIME_TO_LIVE:
            self.write_amf3_value(obj["timeToLive"])
        if f1 & _AM_CLIENT_ID_BYTES:
            self.write_amf3_value(obj["clientIdBytes"])
        if f1 & _AM_MSG_ID_BYTES:
            self.write_amf3_value(obj["messageIdBytes"])

        # --- Subclass flags ---
        is_async = cls in (
            "flex.messaging.messages.AsyncMessage",
            "flex.messaging.messages.AsyncMessageExt",
            "flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage",
            "DSK", "DSA",
        )
        is_ack = cls in (
            "flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage",
            "DSK",
        )
        is_command = cls in (
            "flex.messaging.messages.CommandMessage",
            "flex.messaging.messages.CommandMessageExt",
            "DSC",
        )

        if is_async:
            sf0 = 0
            if "correlationId" in obj:
                sf0 |= _ASYNC_CORRELATION_ID
            if "correlationIdBytes" in obj:
                sf0 |= _ASYNC_CORRELATION_ID_BYTES
            self.write_u8(sf0)
            if sf0 & _ASYNC_CORRELATION_ID:
                self.write_amf3_value(obj["correlationId"])
            if sf0 & _ASYNC_CORRELATION_ID_BYTES:
                self.write_amf3_value(obj["correlationIdBytes"])

            if is_ack:
                self.write_u8(0)  # AcknowledgeMessage flags (usually empty)

                if cls == "flex.messaging.messages.ErrorMessage":
                    ef0 = 0
                    if "extendedData" in obj:
                        ef0 |= 0x01
                    if "faultCode" in obj:
                        ef0 |= 0x02
                    if "faultDetail" in obj:
                        ef0 |= 0x04
                    if "faultString" in obj:
                        ef0 |= 0x08
                    if "rootCause" in obj:
                        ef0 |= 0x10
                    self.write_u8(ef0)
                    if ef0 & 0x01:
                        self.write_amf3_value(obj["extendedData"])
                    if ef0 & 0x02:
                        self.write_amf3_value(obj["faultCode"])
                    if ef0 & 0x04:
                        self.write_amf3_value(obj["faultDetail"])
                    if ef0 & 0x08:
                        self.write_amf3_value(obj["faultString"])
                    if ef0 & 0x10:
                        self.write_amf3_value(obj["rootCause"])

        elif is_command:
            sf0 = 0
            if "operation" in obj:
                sf0 |= _CMD_OPERATION
            self.write_u8(sf0)
            if sf0 & _CMD_OPERATION:
                self.write_amf3_value(obj["operation"])

    def write_amf0_value(self, val):
        if val is None:
            self.write_u8(AMF0_NULL)
        elif isinstance(val, bool):
            self.write_u8(AMF0_BOOLEAN)
            self.write_u8(1 if val else 0)
        elif isinstance(val, (int, float)) and not isinstance(val, bool):
            self.write_u8(AMF0_NUMBER)
            self.write_double(float(val))
        elif isinstance(val, str):
            self.write_u8(AMF0_STRING)
            self.write_amf0_utf8(val)
        elif isinstance(val, list):
            self.write_u8(AMF0_AMF3)
            self.write_amf3_value(val)
        elif isinstance(val, dict):
            amf_type = val.get("__amf_type", "")
            if amf_type == "undefined":
                self.write_u8(AMF0_UNDEFINED)
            elif amf_type == "amf0_object":
                self.write_u8(AMF0_OBJECT)
                for k, v in val.items():
                    if k == "__amf_type":
                        continue
                    self.write_amf0_utf8(k)
                    self.write_amf0_value(v)
                self.write_amf0_utf8("")
                self.write_u8(AMF0_OBJ_END)
            elif amf_type == "amf0_typed":
                self.write_u8(AMF0_TYPED_OBJ)
                self.write_amf0_utf8(val.get("__class", ""))
                for k, v in val.items():
                    if k in ("__amf_type", "__class"):
                        continue
                    self.write_amf0_utf8(k)
                    self.write_amf0_value(v)
                self.write_amf0_utf8("")
                self.write_u8(AMF0_OBJ_END)
            elif amf_type == "amf0_ecma_array":
                self.write_u8(AMF0_ECMA_ARRAY)
                items = {k: v for k, v in val.items() if k != "__amf_type"}
                self.write_u32(len(items))
                for k, v in items.items():
                    self.write_amf0_utf8(k)
                    self.write_amf0_value(v)
                self.write_amf0_utf8("")
                self.write_u8(AMF0_OBJ_END)
            elif amf_type == "amf0_date":
                self.write_u8(AMF0_DATE)
                self.write_double(val.get("ms", 0.0))
                self.buf += struct.pack('>h', val.get("tz", 0))
            elif amf_type == "amf0_xml":
                self.write_u8(AMF0_XML)
                self.write_amf0_long_utf8(val.get("value", ""))
            elif amf_type == "amf0_unknown":
                self.write_u8(val.get("marker", 0))
                self.buf += base64.b64decode(val.get("raw_b64", ""))
            else:
                self.write_u8(AMF0_AMF3)
                self.write_amf3_value(val)
        else:
            self.write_u8(AMF0_NULL)

    # --- Envelope ---

    def write_amf_envelope(self, envelope):
        self.write_u16(envelope.get("amf_version", 3))

        headers = envelope.get("headers", [])
        self.write_u16(len(headers))
        for hdr in headers:
            self.write_amf0_utf8(hdr.get("name", ""))
            self.write_u8(1 if hdr.get("must_understand", False) else 0)
            tmp = AMFEncoder()
            tmp.string_table = self.string_table
            tmp.object_table = self.object_table
            tmp.trait_table = self.trait_table
            tmp.write_amf0_value(hdr.get("value"))
            body_bytes = tmp.get_bytes()
            self.write_i32(len(body_bytes))
            self.buf += body_bytes

        bodies = envelope.get("bodies", [])
        self.write_u16(len(bodies))
        for body in bodies:
            self.write_amf0_utf8(body.get("target", "null"))
            self.write_amf0_utf8(body.get("response", "/1"))
            self.string_table = []
            self.object_table = []
            self.trait_table = []
            tmp = AMFEncoder()
            tmp.write_amf0_value(body.get("value"))
            body_bytes = tmp.get_bytes()
            self.write_i32(len(body_bytes))
            self.buf += body_bytes


# --- Detection helpers ---

def _is_amf_body(body_bytes):
    """Check if body is AMF binary format."""
    if len(body_bytes) < 6:
        return False
    version = struct.unpack('>H', body_bytes[:2])[0]
    if version not in (0, 3):
        return False
    header_count = struct.unpack('>H', body_bytes[2:4])[0]
    if header_count > 100:
        return False
    return True


def _is_amf_content_type(headers):
    """Check Content-Type for AMF."""
    ct = headers.get('Content-Type', headers.get('content-type', ''))
    return 'application/x-amf' in ct


AMF_JSON_MARKER = '"amf_version"'


def _is_amf_json(body_bytes):
    """Check if body is our AMF-JSON editable format."""
    try:
        head = body_bytes[:200].decode('utf-8', errors='replace')
        return AMF_JSON_MARKER in head
    except:
        return False


# --- Plugin class ---

class AMFPlugin(BodyTransformPlugin):
    """Plugin for AMF binary <-> JSON transformation.

    Inbound (Fiddler -> Burp): AMF binary -> readable JSON for editing
    Outbound (Burp -> target): JSON -> AMF binary
    """

    name = "AMF"

    def __init__(self, decode_response=True):
        self.decode_response = decode_response

    def should_transform_inbound(self, body, headers):
        return _is_amf_content_type(headers) or _is_amf_body(body)

    def transform_inbound(self, body, headers):
        try:
            dec = AMFDecoder(body)
            envelope = dec.read_amf_envelope()
            json_str = json.dumps(envelope, indent=2, ensure_ascii=False, default=str)
            new_body = json_str.encode('utf-8')
            print("[Plugin:AMF] AMF binary -> JSON (%d -> %d bytes)" % (len(body), len(new_body)))
            return new_body, {'Content-Type': 'application/json', 'X-AMF-Converted': 'true'}
        except Exception as e:
            print("[Plugin:AMF] Decode error: %s" % e)
            traceback.print_exc()
            return body, {}

    def should_transform_outbound(self, body, headers):
        return _is_amf_json(body)

    def transform_outbound(self, body, headers):
        try:
            json_str = body.decode('utf-8')
            envelope = json.loads(json_str)
            enc = AMFEncoder()
            enc.write_amf_envelope(envelope)
            amf_body = enc.get_bytes()
            print("[Plugin:AMF] JSON -> AMF binary (%d -> %d bytes)" % (len(body), len(amf_body)))
            return amf_body, {'Content-Type': 'application/x-amf'}
        except Exception as e:
            print("[Plugin:AMF] Encode error: %s" % e)
            traceback.print_exc()
            return body, {}

    def should_transform_response(self, body, headers):
        return self.decode_response and (_is_amf_content_type(headers) or _is_amf_body(body))

    # Large response threshold (512KB)
    SUMMARY_THRESHOLD = 512 * 1024

    def transform_response_decode(self, body, headers):
        """AMF response binary -> JSON (for viewing/editing in Burp).
        Large responses are saved to file and a summary is sent to Burp."""
        try:
            dec = AMFDecoder(body)
            envelope = dec.read_amf_envelope()

            envelope["__amf_original_b64"] = base64.b64encode(body).decode()
            json_str = json.dumps(envelope, indent=2, ensure_ascii=False, default=str)

            if len(json_str) > self.SUMMARY_THRESHOLD:
                # Save full data + original AMF binary to file
                import tempfile as _tempfile
                save_dir = os.path.join(_tempfile.gettempdir(), 'amf_responses')
                os.makedirs(save_dir, exist_ok=True)
                ts = time.strftime('%Y%m%d_%H%M%S')
                filepath = os.path.join(save_dir, 'resp_%s.json' % ts)
                rawpath = os.path.join(save_dir, 'resp_%s.amf' % ts)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                with open(rawpath, 'wb') as f:
                    f.write(body)

                # Build summary
                summary = _build_response_summary(envelope, filepath)
                summary["__amf_raw_file"] = rawpath.replace('\\', '/')
                summary_str = json.dumps(summary, indent=2, ensure_ascii=False, default=str)
                new_body = summary_str.encode('utf-8')

                # Console output
                print("[Plugin:AMF] Response AMF -> JSON (%d -> %s)" % (len(body), _human_size(len(json_str))))
                print("[Plugin:AMF] Full data saved: %s" % filepath)
                _print_console_table(envelope)

                return new_body, {'Content-Type': 'application/json', 'X-AMF-Response-Converted': 'true'}
            else:
                new_body = json_str.encode('utf-8')
                print("[Plugin:AMF] Response AMF -> JSON (%d -> %d bytes)" % (len(body), len(new_body)))
                return new_body, {'Content-Type': 'application/json', 'X-AMF-Response-Converted': 'true'}
        except Exception as e:
            print("[Plugin:AMF] Response decode error: %s" % e)
            traceback.print_exc()
            return body, {}

    def transform_response_encode(self, body, headers):
        """Restore original AMF binary for client."""
        try:
            text = body.decode('utf-8', errors='replace')
            head = text[:200]

            if '__amf_summary' in head:
                obj = json.loads(text)
                raw_file = obj.get("__amf_raw_file", "")
                if raw_file and os.path.exists(raw_file):
                    with open(raw_file, 'rb') as f:
                        amf_body = f.read()
                    print("[Plugin:AMF] Response restored from file (%d bytes)" % len(amf_body))
                    return amf_body, {'Content-Type': 'application/x-amf'}

            if '__amf_original_b64' in text:
                obj = json.loads(text)
                if "__amf_original_b64" in obj:
                    amf_body = base64.b64decode(obj["__amf_original_b64"])
                    print("[Plugin:AMF] Response restored from original (%d bytes)" % len(amf_body))
                    return amf_body, {'Content-Type': 'application/x-amf'}

            if 'amf_version' in head:
                obj = json.loads(text)
                enc = AMFEncoder()
                enc.write_amf_envelope(obj)
                amf_body = enc.get_bytes()
                print("[Plugin:AMF] Response re-encoded (%d bytes)" % len(amf_body))
                return amf_body, {'Content-Type': 'application/x-amf'}

        except Exception as e:
            print("[Plugin:AMF] Response encode error: %s" % e)
            traceback.print_exc()
            return body, {}


# ============================================================
# Response Summary + Console Table + CLI Analysis Tool
# ============================================================

def _human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return "%.1f%s" % (n, unit)
        n /= 1024
    return "%.1fTB" % n


def _flatten_record(record):
    """Flatten a record: unwrap externalizable wrappers, keep scalars only."""
    if isinstance(record, dict):
        cls = record.get("__class", "")
        if record.get("__externalizable") and "value" in record:
            return _flatten_record(record.get("value", record))
        if "result" in record:
            inner = record["result"]
            if isinstance(inner, dict) and any(k for k in inner if not k.startswith("__")):
                return _flatten_record(inner)
        result = {}
        for k, v in record.items():
            if k in ("__amf_type", "__class", "__externalizable"):
                continue
            if not isinstance(v, (dict, list)):
                result[k] = v
        return result if result else record
    return record


def _find_records(obj, path=""):
    """Recursively find arrays of data records."""
    results = []
    if isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            results.append((path, obj))
        return results
    if isinstance(obj, dict):
        cls = obj.get("__class", "")
        if obj.get("__externalizable") and isinstance(obj.get("value"), list):
            val = obj.get("value", [])
            if isinstance(val, list) and val:
                results.append((path + "." + cls if path else cls, val))
                return results
        for key, val in obj.items():
            if key.startswith("__"):
                continue
            sub = _find_records(val, path + "." + key if path else key)
            results.extend(sub)
    return results


def _count_raw_b64(obj):
    """Count __raw_b64 fields recursively."""
    if isinstance(obj, dict):
        count = 1 if "__raw_b64" in obj else 0
        for v in obj.values():
            count += _count_raw_b64(v)
        return count
    if isinstance(obj, list):
        return sum(_count_raw_b64(item) for item in obj)
    return 0


def _build_response_summary(envelope, filepath):
    """Build a compact summary of a decoded AMF envelope."""
    summary = {
        "__amf_summary": ">>> THIS IS A SUMMARY - NOT ACTUAL DATA. Full data saved to file below. <<<",
    }

    for body in envelope.get("bodies", []):
        target = body.get("target", "")
        value = body.get("value", {})
        cls = value.get("__class", "") if isinstance(value, dict) else ""
        summary["target"] = target
        summary["class"] = cls

        if isinstance(value, dict):
            for key in ("timestamp", "messageId", "correlationId"):
                if key in value:
                    summary[key] = value[key]

        # Find records
        records_found = _find_records(value)
        if records_found:
            path, arr = records_found[0]
            summary["record_path"] = path
            summary["record_count"] = len(arr)

            # Columns + sample
            flat_samples = []
            columns = []
            col_set = set()
            for r in arr[:100]:
                flat = _flatten_record(r)
                if isinstance(flat, dict) and len(flat) > 0:
                    for k in flat:
                        if k not in col_set:
                            columns.append(k)
                            col_set.add(k)
                    flat_samples.append(flat)
                    if len(flat_samples) >= 3:
                        break

            summary["columns"] = columns
            summary["sample_data"] = flat_samples

    summary["raw_b64_fields"] = _count_raw_b64(envelope)
    fp = filepath.replace('\\', '/')
    summary["full_data_file"] = fp
    summary["usage"] = [
        "python -m amesianx.plugins.amf %s --list" % fp,
        "python -m amesianx.plugins.amf %s --list --limit 100" % fp,
        "python -m amesianx.plugins.amf %s --list --search keyword" % fp,
        "python -m amesianx.plugins.amf %s --list --deep" % fp,
        "python -m amesianx.plugins.amf %s --json" % fp,
    ]
    summary["options"] = {
        "--list": "Show records as table",
        "--limit N": "Max rows (default 50)",
        "--search TEXT": "Filter rows containing text",
        "--deep": "Deep parse raw_b64 fields",
        "--json": "Full JSON dump",
    }

    return summary


def _print_console_table(envelope, max_rows=5):
    """Print a brief table preview to console."""
    for body in envelope.get("bodies", []):
        target = body.get("target", "")
        value = body.get("value", {})
        cls = value.get("__class", "") if isinstance(value, dict) else ""

        records_found = _find_records(value)
        if not records_found:
            continue

        path, arr = records_found[0]
        print("\n  %s | %s | %d records" % (target, cls, len(arr)))

        flat_rows = []
        columns = []
        col_set = set()
        for r in arr[:200]:
            flat = _flatten_record(r)
            if isinstance(flat, dict) and len(flat) > 0:
                for k in flat:
                    if k not in col_set:
                        columns.append(k)
                        col_set.add(k)
                flat_rows.append(flat)

        if not flat_rows:
            continue

        # Column widths
        widths = {c: min(max(len(c), max((len(str(r.get(c, ""))) for r in flat_rows[:50]), default=0)), 20) for c in columns}

        # Header
        hdr = " | ".join(c.ljust(widths[c])[:20] for c in columns)
        sep = "-+-".join("-" * min(widths[c], 20) for c in columns)
        print("  " + hdr)
        print("  " + sep)
        for r in flat_rows[:max_rows]:
            row = " | ".join(str(r.get(c, "")).ljust(widths[c])[:20] for c in columns)
            print("  " + row)
        print("  " + sep)
        print("  (%d / %d shown)" % (min(max_rows, len(flat_rows)), len(arr)))


def _deep_decode_raw_b64(envelope):
    """Re-decode __raw_b64 fields using tail-scanning BlazeDS parser."""
    for body in envelope.get("bodies", []):
        value = body.get("value", {})
        if isinstance(value, dict) and "__raw_b64" in value:
            cls = value.get("__class", "")
            raw = base64.b64decode(value["__raw_b64"])

            env_bytes = bytearray()
            env_bytes += b'\x00\x03\x00\x00\x00\x01'
            target = body.get("target", "/1/onResult").encode('utf-8')
            env_bytes += struct.pack('>H', len(target)) + target
            response = body.get("response", "").encode('utf-8')
            env_bytes += struct.pack('>H', len(response)) + response

            amf_body = bytearray()
            amf_body += b'\x11\x0a\x07'
            cls_bytes = cls.encode('utf-8')
            str_ref = (len(cls_bytes) << 1) | 1
            if str_ref < 0x80:
                amf_body += bytes([str_ref])
            elif str_ref < 0x4000:
                amf_body += bytes([(str_ref >> 7) | 0x80, str_ref & 0x7F])
            else:
                amf_body += bytes([(str_ref >> 14) | 0x80, (str_ref >> 7) | 0x80, str_ref & 0x7F])
            amf_body += cls_bytes
            amf_body += raw

            env_bytes += struct.pack('>i', len(amf_body))
            env_bytes += amf_body

            try:
                dec = AMFDecoder(bytes(env_bytes))
                new_envelope = dec.read_amf_envelope()
                body["value"] = new_envelope["bodies"][0]["value"]
            except Exception as e:
                print("[WARN] Deep decode failed for %s: %s" % (cls, e))

    return envelope


# ============================================================
# CLI Mode: python -m amesianx.plugins.amf <file> [options]
# ============================================================

def _cli_main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='AMF Decode Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s response.json --list
  %(prog)s response.json --list --limit 20
  %(prog)s response.json --list --search "admin"
  %(prog)s response.json --list --deep
  %(prog)s response.json --json
  %(prog)s response.json --json --deep
""")
    parser.add_argument('file', help='AMF response file (JSON or raw hex dump)')
    parser.add_argument('--json', action='store_true', help='Output full decoded JSON')
    parser.add_argument('--list', action='store_true', help='Show data records as table')
    parser.add_argument('--limit', type=int, default=50, help='Max rows to display (default: 50)')
    parser.add_argument('--search', type=str, default=None, help='Filter rows containing text')
    parser.add_argument('--deep', action='store_true', help='Deep parse raw_b64 fields (tail-scanning)')
    args = parser.parse_args()

    # Load file
    with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    if '"amf_version"' in text[:500] or '"__amf_summary"' in text[:500]:
        json_start = text.index('{')
        envelope = json.loads(text[json_start:])

        # If this is a summary, use the full_data_file
        if envelope.get("__amf_summary"):
            full_path = envelope.get("full_data_file", "")
            if full_path and os.path.exists(full_path):
                print("[*] Loading full data from: %s" % full_path)
                with open(full_path, 'r', encoding='utf-8') as f2:
                    envelope = json.loads(f2.read())
            else:
                print("[!] Summary file — full data not found at: %s" % full_path)
                print(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
                return
        print("[*] Loaded JSON envelope")
    else:
        # Try hex dump → raw AMF
        hex_bytes = []
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('HTTP') or line.startswith('---'):
                continue
            for part in line.split():
                if len(part) == 2:
                    try:
                        hex_bytes.append(int(part, 16))
                    except ValueError:
                        break
        if hex_bytes:
            print("[*] Decoding raw AMF binary (%d bytes)" % len(hex_bytes))
            dec = AMFDecoder(bytes(hex_bytes))
            envelope = dec.read_amf_envelope()
        else:
            print("[!] Cannot detect AMF data in file")
            sys.exit(1)

    # Deep decode
    if args.deep:
        raw_check = json.dumps(envelope, default=str)
        if '__raw_b64' in raw_check:
            print("[*] Deep parsing raw_b64 fields...")
            envelope = _deep_decode_raw_b64(envelope)

    # Output
    if args.json:
        envelope.pop("__amf_original_b64", None)
        print(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        return

    # Default: show summary + table
    for i, body in enumerate(envelope.get("bodies", [])):
        target = body.get("target", "")
        value = body.get("value", {})
        cls = value.get("__class", "") if isinstance(value, dict) else ""
        print("\n[Body %d] target=%s class=%s" % (i, target, cls))

        if isinstance(value, dict):
            for key in ("timestamp", "messageId", "correlationId"):
                if key in value:
                    print("  %s: %s" % (key, value[key]))

        records_found = _find_records(value)
        if not records_found:
            val_str = json.dumps(value, indent=2, ensure_ascii=False, default=str)
            print(val_str[:3000])
            continue

        for path, arr in records_found:
            print("\n  [%s] %d records" % (path, len(arr)))

            if not args.list:
                print("  (use --list to display as table)")
                continue

            # Flatten + filter + print
            flat_rows = []
            columns = []
            col_set = set()
            for r in arr:
                flat = _flatten_record(r)
                if isinstance(flat, dict) and len(flat) > 0:
                    if args.search:
                        vals_str = ' '.join(str(v) for v in flat.values())
                        if args.search.lower() not in vals_str.lower():
                            continue
                    for k in flat:
                        if k not in col_set:
                            columns.append(k)
                            col_set.add(k)
                    flat_rows.append(flat)

            total = len(flat_rows)
            display = flat_rows[:args.limit]

            if not display:
                print("  (no matching records)")
                continue

            # Column widths
            widths = {}
            for c in columns:
                widths[c] = len(c)
                for r in display:
                    widths[c] = max(widths[c], min(len(str(r.get(c, ""))), 30))

            hdr = " | ".join(c.ljust(widths[c])[:30] for c in columns)
            sep = "-+-".join("-" * min(widths[c], 30) for c in columns)
            print(hdr)
            print(sep)
            for r in display:
                row = " | ".join(str(r.get(c, "")).ljust(widths[c])[:30] for c in columns)
                print(row)
            print(sep)
            print("Showing %d / %d records" % (len(display), total))


if __name__ == '__main__':
    _cli_main()
