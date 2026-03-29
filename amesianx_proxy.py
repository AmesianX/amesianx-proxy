#!/usr/bin/env python3
"""
Amesianx Proxy — General-purpose proxy tool (red team edition)

Flow:
  Browser -> Fiddler(8888) -> Proxy-IN(8089) [plugin transform] -> Burp(8080) [edit]
  Burp -> Proxy-OUT(8099) [plugin reverse-transform] -> Target Server

Usage:
  python amesianx_proxy.py --listen-in 8089 --listen-out 8099 --burp 8080
  python amesianx_proxy.py --no-nexacro          # pure proxy, no plugins
  python amesianx_proxy.py --gen-cert             # generate fresh cert via openssl
  python amesianx_proxy.py --test
"""

import http.server
import http.client
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
import threading
import socket
import select
import sys
import argparse
import ssl
import traceback
import tempfile
import os
import subprocess
import socketserver


# ============================================================
# Section 0: Embedded Certificate PEM Constants
# ============================================================

EMBEDDED_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUXDtdSfpaOm2PrGT++eTk2m0aBmkwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNQW1lc2lhbnhQcm94eTAgFw0yNjAzMjMwNzA4MjFaGA8y
MTI2MDIyNzA3MDgyMVowGDEWMBQGA1UEAwwNQW1lc2lhbnhQcm94eTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKKE2AzAgWpmn2+osGIWa7MhafXOdUv
iUcGV9vYL4FPdLgTMDxMGSSnOZ2FDNnS5hXMzjN+ZTNNu2xne1VdN7FwzyD/qG3V
840w6p3Bb6vqnP/k+C+94LmuGnsLvSRe2ICz/D2lTsvLsDzyWUjU3wsqvBy0gffN
2RA67EjuupT0/hBDCeA5Gsa35k2wPKjpTFJpRCfNlIHvVzMqITaGqcdwb7YecwD1
LwN8gDzpoFQhRJ8TcU/Y19T5Kt1liN6AKLD7ZAkcuLdGDACx26+eQD7NFryoQStv
VqdNEiFLSdpIduBmRUfO7SFp/aYLbO80PQGqfRvM4o+zTzGCDQSxRNsCAwEAAaNv
MG0wHQYDVR0OBBYEFP3lTkFxe+IZ/y/ueuIOu19IK7t2MB8GA1UdIwQYMBaAFP3l
TkFxe+IZ/y/ueuIOu19IK7t2MA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJ
bG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCSCEBjGurD3kvkgF03
aPEXle2OcesS3MngfX4zJIt6+TTCS1e375NFim61XEL98NTxlCbJ8aMgGWeoIt5Y
ihum84jeBka1jlsGiMxFlmzemfKkJio34KbMcA2+SB3CRClQ/+WYFScU9vzK1bp9
78OXYR+TtHC9v+8tA5LJZSGEwuyKStLHeT/PDl4knwNLa2ZRLhxDH2n/2YA7BG1T
/Mrvb9rX1KKGHo++HDvfxK57NXjM6euCwO07Ew04XUeUdp7kcaqCO7QWR8HyGKwT
qwMhw0ZTY6vuRIED2Yd+b8aWxHil+v9MqSMnqVC5sUcgeh0po1vTwy+CX82jaXIu
1ya+
-----END CERTIFICATE-----
"""

EMBEDDED_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCihNgMwIFqZp9
vqLBiFmuzIWn1znVL4lHBlfb2C+BT3S4EzA8TBkkpzmdhQzZ0uYVzM4zfmUzTbts
Z3tVXTexcM8g/6ht1fONMOqdwW+r6pz/5PgvveC5rhp7C70kXtiAs/w9pU7Ly7A8
8llI1N8LKrwctIH3zdkQOuxI7rqU9P4QQwngORrGt+ZNsDyo6UxSaUQnzZSB71cz
KiE2hqnHcG+2HnMA9S8DfIA86aBUIUSfE3FP2NfU+SrdZYjegCiw+2QJHLi3RgwA
sduvnkA+zRa8qEErb1anTRIhS0naSHbgZkVHzu0haf2mC2zvND0Bqn0bzOKPs08x
gg0EsUTbAgMBAAECggEAJ6PO8ukx3kmC62Bu9ZR9Abs2+M5IQIJhLJHEEU2p0GWK
WP+/8mlnLirM+KXlynTI4WRMF/4HTP7n09z6KpjGAmgELKsrfMX9zKVNCTwjLxqt
Rw826zN7mRo61xu7PK/+2arTGRSYC7rDfIe9XbPShwn8LrUxTncpZb876liKuFMg
bpLmsLgKHQQb/1f6r+IKSZGb3uOcjZLtg7f4XG+hioCpjliWMLUmusLRxxailT/7
3pwQNbE+nGqaQcgLcCuzfVdTUisb5awSAOfjJ+93xKnzDnQZRUuZGslsmKGFIccU
r9Kh8h+UTvIO2g+AounB2UHaCXi1P8ePxrFB7YS/QQKBgQDpwObF6s85IumRRZoC
FreoB2XaOcsdCQZ6ozo8SvgYqcKD8LibtKksA2WZoEUIAae/zuMWkLgYq4Y0msyL
OxrL3q+4+GG5pMXx/fcxKzsNG3+WHyxcFOKQ9GEfwu4u9EZKq3squ8CNKCT0W76b
lftTbwsKVXDy710G5Kr3NescUQKBgQDVDcXBJdyyCfq2CzFfkoZo1ZQBv7RDOs7O
tXt9n3N15D3GEB7wYuRjUESrTQBtTmZTudZuHP8ATx1VpOWmBqNKA71CNq3rxaDP
9NBJ+p4sWV5NChSmJPzVhrRxAadp5L06ONeXwL7Fhx9tlj72pVvw6ij9T/L77J6G
Sr/+BYy/awKBgQCJe82/xrWO83vQ19EXPWlTyNYdHjTapP5Mj0inQajeSKqBk8ng
usdtfan6S4uOg/q4E+T41rGQwQG0Wv/HPEIsepN8BYrk94b9J9SF9NlMgknub/NV
TWtcun+NgMc6kq3tKSLOJZPA8kWZ+4QGWpZxojQqJcrC+AoNDd2IfQwFoQKBgD2m
YpblcdtC7/1Fd+AD8kjbpJxs8KiTl8xQz48mWK7AgO+TMqC0vQnP7E71VS5MBWgs
2lO6qD9apU5nDNziBtYgBt/mGqWi5knGuY7uql6C7bq1NAxvn4naFNSuedc2jVsP
n7MV3x4hX4LCey2748LuvzWtsM4dRjHt52iGCphJAoGAAstwhn5T4z/EcR40WWYW
wKYJu2n9AITmeJeEUanWqfd/EiGl9JG9wf96g27ArSs3z14GTj4StMcnhR8qLoY6
SPfN9JO5iphXJAwHfa7xnXOnEOG7yb6w3xHtpebRLOHyLGHKHsHqhv/YkgpwznJB
0GAcxsFrfioXgx6FSIvR5AM=
-----END PRIVATE KEY-----
"""


# ============================================================
# Section 1: BodyTransformPlugin Base Class
# ============================================================

class BodyTransformPlugin:
    """Base class for body transformation plugins.

    Subclasses implement detection and transformation for both directions:
      - Inbound (client -> Burp): decode wire format to editable format
      - Outbound (Burp -> target): re-encode editable format to wire format

    transform_* methods return (new_body_bytes, extra_headers_dict).
    """

    name = "BasePlugin"

    def should_transform_inbound(self, body, headers):
        """Return True if this plugin should handle inbound transformation."""
        return False

    def transform_inbound(self, body, headers):
        """Transform body for inbound direction (wire -> editable).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def should_transform_outbound(self, body, headers):
        """Return True if this plugin should handle outbound transformation."""
        return False

    def transform_outbound(self, body, headers):
        """Transform body for outbound direction (editable -> wire).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def should_transform_response(self, body, headers):
        """Return True if this plugin should handle response transformation."""
        return False

    def transform_response_decode(self, body, headers):
        """Transform response body: wire -> editable (for viewing in Burp).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def transform_response_encode(self, body, headers):
        """Transform response body: editable -> wire (restore before sending to client).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}


# ============================================================
# Section 2: NexacroSSVPlugin
# ============================================================

# Nexacro SSV delimiters
RS = '\x1e'  # Record Separator (row delimiter)
US = '\x1f'  # Unit Separator (column delimiter)
ETX = '\x03'  # Undefined/null sentinel

NEXACRO_NS = "http://www.nexacroplatform.com/platform/dataset"


def _parse_column_def(col_str):
    """Parse column definition like 'BEANID:STRING(32)' -> (name, type, size)"""
    if ':' in col_str:
        parts = col_str.split(':')
        name = parts[0]
        type_info = parts[1]
        if '(' in type_info:
            dtype = type_info[:type_info.index('(')]
            size = type_info[type_info.index('(') + 1:type_info.index(')')]
        else:
            dtype = type_info
            size = ""
        return name, dtype, size
    return col_str, "STRING", "256"


def _is_ssv_body(body_bytes):
    """Check if body is SSV format"""
    try:
        body_str = body_bytes.decode('utf-8', errors='replace')
        if body_str.startswith('SSV:'):
            return True
        if body_str.startswith('SSV%3A') or body_str.startswith('SSV%3a'):
            return True
        head = body_str[:200]
        if '%1E' in head or '%1e' in head:
            if 'Dataset' in body_str or 'SSV' in head:
                return True
    except:
        pass
    return False


def _is_nexacro_xml(body_bytes):
    """Check if body is Nexacro XML format"""
    try:
        body_str = body_bytes.decode('utf-8', errors='replace')
        return '<?xml' in body_str[:100] and NEXACRO_NS in body_str[:500]
    except:
        return False


def _ssv_to_xml(body_bytes):
    """Convert Nexacro SSV format to readable XML"""
    try:
        body = body_bytes.decode('utf-8', errors='replace')
    except:
        body = body_bytes.decode('latin-1')

    if '%1E' in body or '%1e' in body or '%1F' in body or '%1f' in body:
        body = urllib.parse.unquote(body)

    records = body.split(RS)

    parameters = []
    datasets = []
    current_dataset = None

    i = 0
    while i < len(records):
        record = records[i]
        i += 1

        if not record or record.isspace():
            continue

        if record.startswith('SSV:'):
            continue

        if record.startswith('Dataset:'):
            if current_dataset:
                datasets.append(current_dataset)
            ds_name = record[len('Dataset:'):]
            current_dataset = {
                'name': ds_name,
                'const_cols': [],
                'const_vals': [],
                'columns': [],
                'rows': []
            }
            continue

        if current_dataset is not None:
            fields = record.split(US)

            if fields[0] == '_Const_':
                for f in fields[1:]:
                    if '=' in f:
                        col_part, val = f.split('=', 1)
                        name, dtype, size = _parse_column_def(col_part)
                        current_dataset['const_cols'].append((name, dtype, size))
                        current_dataset['const_vals'].append(val)
                continue

            if fields[0] == '_RowType_':
                for f in fields[1:]:
                    if f:
                        name, dtype, size = _parse_column_def(f)
                        current_dataset['columns'].append((name, dtype, size))
                continue

            if len(fields[0]) <= 1 and fields[0] in ('N', 'I', 'U', 'D'):
                row_type = fields[0]
                values = fields[1:]
                current_dataset['rows'].append((row_type, values))
                continue

        if '=' in record and current_dataset is None:
            key, val = record.split('=', 1)
            parameters.append((key, val))
            continue

    if current_dataset:
        datasets.append(current_dataset)

    # Build XML
    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<Root xmlns="%s">' % NEXACRO_NS)

    if parameters:
        lines.append('  <Parameters>')
        for key, val in parameters:
            if val:
                lines.append('    <Parameter id="%s">%s</Parameter>' % (xml_escape(key), xml_escape(val)))
            else:
                lines.append('    <Parameter id="%s" />' % xml_escape(key))
        lines.append('  </Parameters>')
    else:
        lines.append('  <Parameters />')

    for ds in datasets:
        lines.append('  <Dataset id="%s">' % xml_escape(ds['name']))

        if ds['const_cols']:
            lines.append('    <ConstInfo>')
            for idx, (name, dtype, size) in enumerate(ds['const_cols']):
                val = ds['const_vals'][idx] if idx < len(ds['const_vals']) else ''
                if val and val != ETX:
                    lines.append('      <Const id="%s" type="%s" size="%s">%s</Const>' % (name, dtype, size, xml_escape(val)))
                else:
                    lines.append('      <Const id="%s" type="%s" size="%s" />' % (name, dtype, size))
            lines.append('    </ConstInfo>')

        if ds['columns']:
            lines.append('    <ColumnInfo>')
            for name, dtype, size in ds['columns']:
                lines.append('      <Column id="%s" type="%s" size="%s" />' % (name, dtype, size))
            lines.append('    </ColumnInfo>')

        if ds['rows']:
            lines.append('    <Rows>')
            for row_type, values in ds['rows']:
                lines.append('      <Row type="%s">' % row_type)
                for idx, (name, dtype, size) in enumerate(ds['columns']):
                    val = values[idx] if idx < len(values) else ''
                    if val == ETX:
                        lines.append('        <Col id="%s" null="true" />' % name)
                    elif val:
                        lines.append('        <Col id="%s">%s</Col>' % (name, xml_escape(val)))
                    else:
                        lines.append('        <Col id="%s"></Col>' % name)
                lines.append('      </Row>')
            lines.append('    </Rows>')

        lines.append('  </Dataset>')

    lines.append('</Root>')
    return '\n'.join(lines)


def _xml_to_ssv(xml_str):
    """Convert Nexacro XML back to SSV format"""
    xml_str = xml_str.replace(' xmlns="%s"' % NEXACRO_NS, '')
    xml_str = xml_str.replace(' xmlns=""', '')

    root = ET.fromstring(xml_str)

    parts = []
    parts.append('SSV:utf-8')

    params_elem = root.find('Parameters')
    if params_elem is not None:
        for param in params_elem.findall('Parameter'):
            pid = param.get('id', '')
            val = param.text or ''
            parts.append('%s=%s' % (pid, val))

    for ds_elem in root.findall('Dataset'):
        ds_name = ds_elem.get('id', '')
        parts.append('Dataset:%s' % ds_name)

        const_elem = ds_elem.find('ConstInfo')
        if const_elem is not None:
            const_fields = ['_Const_']
            for const in const_elem.findall('Const'):
                cid = const.get('id', '')
                ctype = const.get('type', 'STRING')
                csize = const.get('size', '256')
                val = const.text or ''
                const_fields.append('%s:%s(%s)=%s' % (cid, ctype, csize, val))
            parts.append(US.join(const_fields))

        col_info = ds_elem.find('ColumnInfo')
        columns = []
        if col_info is not None:
            col_fields = ['_RowType_']
            for col in col_info.findall('Column'):
                cid = col.get('id', '')
                ctype = col.get('type', 'STRING')
                csize = col.get('size', '256')
                columns.append(cid)
                col_fields.append('%s:%s(%s)' % (cid, ctype, csize))
            parts.append(US.join(col_fields))

        rows_elem = ds_elem.find('Rows')
        if rows_elem is not None:
            for row in rows_elem.findall('Row'):
                row_type = row.get('type', 'N')
                row_fields = [row_type]

                col_map = {}
                for col_elem in row.findall('Col'):
                    cid = col_elem.get('id', '')
                    is_null = col_elem.get('null', '') == 'true'
                    if is_null:
                        col_map[cid] = ETX
                    else:
                        col_map[cid] = col_elem.text or ''

                for cid in columns:
                    row_fields.append(col_map.get(cid, ''))

                parts.append(US.join(row_fields))

        parts.append('')

    result = RS.join(parts)
    return result.encode('utf-8')


class NexacroSSVPlugin(BodyTransformPlugin):
    """Plugin for Nexacro SSV <-> XML transformation."""

    name = "NexacroSSV"

    def __init__(self, decode_response=True):
        self.decode_response = decode_response

    def should_transform_inbound(self, body, headers):
        return _is_ssv_body(body)

    def transform_inbound(self, body, headers):
        xml_body = _ssv_to_xml(body)
        new_body = xml_body.encode('utf-8')
        print("[Plugin:NexacroSSV] SSV -> XML (%d -> %d bytes)" % (len(body), len(new_body)))
        return new_body, {}

    def should_transform_outbound(self, body, headers):
        return _is_nexacro_xml(body)

    def transform_outbound(self, body, headers):
        body_str = body.decode('utf-8', errors='replace')
        ssv_body = _xml_to_ssv(body_str)
        print("[Plugin:NexacroSSV] XML -> SSV (%d -> %d bytes)" % (len(body), len(ssv_body)))
        return ssv_body, {'Content-Type': 'text/xml'}

    def should_transform_response(self, body, headers):
        return self.decode_response and _is_ssv_body(body)

    def transform_response_decode(self, body, headers):
        try:
            xml_body = _ssv_to_xml(body)
            new_body = xml_body.encode('utf-8')
            print("[Plugin:NexacroSSV] Response SSV -> XML (%d -> %d bytes)" % (len(body), len(new_body)))
            return new_body, {'Content-Type': 'application/xml', 'X-SSV-Response-Converted': 'true'}
        except Exception as e:
            print("[Plugin:NexacroSSV] Response decode error: %s" % e)
            return body, {}

    def transform_response_encode(self, body, headers):
        if not _is_nexacro_xml(body):
            return body, {}
        try:
            body_str = body.decode('utf-8', errors='replace')
            ssv_body = _xml_to_ssv(body_str)
            print("[Plugin:NexacroSSV] Response XML -> SSV (%d -> %d bytes)" % (len(body), len(ssv_body)))
            return ssv_body, {'Content-Type': 'text/xml'}
        except Exception as e:
            print("[Plugin:NexacroSSV] Response encode error: %s" % e)
            return body, {}


# ============================================================
# Section 2.5: AMFPlugin — AMF binary <-> JSON transformation
# ============================================================

import json
import struct as _struct
import base64

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
BLAZEDS_MESSAGE_CLASSES = {
    "flex.messaging.messages.AcknowledgeMessage",
    "flex.messaging.messages.AcknowledgeMessageExt",
    "flex.messaging.messages.CommandMessage",
    "flex.messaging.messages.CommandMessageExt",
    "flex.messaging.messages.RemotingMessage",
    "flex.messaging.messages.AsyncMessage",
    "flex.messaging.messages.AsyncMessageExt",
    "flex.messaging.messages.ErrorMessage",
    "DSK", "DSC", "DSA",
}

_AM_BODY            = 0x01
_AM_CLIENT_ID       = 0x02
_AM_DESTINATION     = 0x04
_AM_HEADERS         = 0x08
_AM_MESSAGE_ID      = 0x10
_AM_TIMESTAMP       = 0x20
_AM_TIME_TO_LIVE    = 0x40
_AM_HAS_NEXT        = 0x80
_AM_CLIENT_ID_BYTES = 0x01
_AM_MSG_ID_BYTES    = 0x02
_ASYNC_CORRELATION_ID       = 0x01
_ASYNC_CORRELATION_ID_BYTES = 0x02
_CMD_OPERATION = 0x01


class AMFDecoder:
    """Decode AMF binary to Python objects."""

    def __init__(self, data):
        self.data = data
        self.pos = 0
        # AMF0 references
        self.amf0_refs = []
        # AMF3 reference tables
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
        return _struct.unpack('>H', self.read_bytes(2))[0]

    def read_u32(self):
        return _struct.unpack('>I', self.read_bytes(4))[0]

    def read_i32(self):
        return _struct.unpack('>i', self.read_bytes(4))[0]

    def read_double(self):
        return _struct.unpack('>d', self.read_bytes(8))[0]

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
            tz = _struct.unpack('>h', self.read_bytes(2))[0]
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
            # Unknown marker — dump remaining as raw
            raw = self.data[self.pos:]
            self.pos = len(self.data)
            return {"__amf_type": "amf0_unknown", "marker": marker,
                    "raw_b64": base64.b64encode(raw).decode()}

    # --- AMF3 ---

    def read_amf3_u29(self):
        """Variable-length unsigned 29-bit integer."""
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
            # Reference
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
            # Sign-extend 29-bit
            if n & 0x10000000:
                n -= 0x20000000
            return n

        elif marker == AMF3_DOUBLE:
            return self.read_double()

        elif marker == AMF3_STRING:
            return self.read_amf3_string()

        elif marker == AMF3_XML_DOC or marker == AMF3_XML:
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
            # Associative portion
            while True:
                key = self.read_amf3_string()
                if key == "":
                    break
                result["assoc"][key] = self.read_amf3_value()
            # Dense portion
            for _ in range(count):
                result["dense"].append(self.read_amf3_value())
            # Simplify if no associative keys
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
            # Object reference
            idx = ref >> 1
            if idx < len(self.object_refs):
                return self.object_refs[idx]
            return {"__amf_type": "object_ref", "index": idx}

        # Inline object
        if (ref & 2) == 0:
            # Trait reference
            trait_idx = ref >> 2
            if trait_idx < len(self.trait_refs):
                traits = self.trait_refs[trait_idx]
            else:
                traits = {"class": "", "externalizable": False, "dynamic": False, "members": []}
        else:
            # Inline traits
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
                    # BlazeDS parsing failed — fallback to raw bytes
                    self.pos = saved_pos
                    raw = self.data[self.pos:]
                    self.pos = len(self.data)
                    # Clean up partially parsed fields
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

        # Sealed members
        for member_name in traits["members"]:
            obj[member_name] = self.read_amf3_value()

        # Dynamic members
        if traits["dynamic"]:
            while True:
                key = self.read_amf3_string()
                if key == "":
                    break
                obj[key] = self.read_amf3_value()

        return obj

    def _read_blazeds_flags(self):
        flags_list = []
        while True:
            b = self.read_u8()
            flags_list.append(b)
            if not (b & 0x80):
                break
        return flags_list

    def _read_blazeds_message_external(self, obj, cls):
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

        # Count non-body tail fields to find where body ends by parsing from the end
        tail_field_count = 0
        if f0 & _AM_CLIENT_ID: tail_field_count += 1
        if f0 & _AM_DESTINATION: tail_field_count += 1
        if f0 & _AM_HEADERS: tail_field_count += 1
        if f0 & _AM_MESSAGE_ID: tail_field_count += 1
        if f0 & _AM_TIMESTAMP: tail_field_count += 1
        if f0 & _AM_TIME_TO_LIVE: tail_field_count += 1
        if f1 & _AM_CLIENT_ID_BYTES: tail_field_count += 1
        if f1 & _AM_MSG_ID_BYTES: tail_field_count += 1

        # Parse tail fields from the end to find body boundary
        # This handles the case where body contains complex nested data
        # whose parsing may consume a different number of bytes than expected
        tail_start = None
        if (f0 & _AM_BODY) and tail_field_count > 0:
            tail_start = self._find_blazeds_tail(f0, f1, is_async, is_ack, is_command, cls)

        if f0 & _AM_BODY:
            if tail_start is not None:
                # Read body as raw bytes up to tail, then decode
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
        """Find the start of tail fields by scanning backwards from end of data.

        BlazeDS tail fields (after body) are small — we parse from the end
        to locate where body data ends and tail fields begin.
        """
        data = self.data
        total = len(data)

        # Try progressively larger tail windows
        for tail_size in (200, 500, 2000):
            if tail_size >= total - self.pos:
                continue
            try:
                # Parse tail fields in order from a candidate start position
                # Strategy: find AMF3_DOUBLE (0x05) for timestamp in the tail,
                # then verify the rest parses correctly to the end
                search_start = total - tail_size
                for i in range(search_start, total - 20):
                    if data[i] != 0x05:  # AMF3_DOUBLE marker
                        continue
                    # Try parsing from before this position
                    # Count fields before timestamp
                    pre_ts_fields = 0
                    if f0 & _AM_CLIENT_ID: pre_ts_fields += 1
                    if f0 & _AM_DESTINATION: pre_ts_fields += 1
                    if f0 & _AM_HEADERS: pre_ts_fields += 1
                    if f0 & _AM_MESSAGE_ID: pre_ts_fields += 1

                    # Timestamp candidate
                    ts_dec = AMFDecoder(data)
                    ts_dec.pos = i
                    try:
                        ts_val = ts_dec.read_amf3_value()
                        if not isinstance(ts_val, float) or ts_val < 1600000000000 or ts_val > 2000000000000:
                            continue
                    except:
                        continue

                    # Try parsing remaining tail fields
                    try:
                        remaining_ok = True
                        # After timestamp: timeToLive, clientIdBytes, messageIdBytes, sub-flags...
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
                                    ts_dec.read_u8()  # ack flags
                            elif is_command:
                                if sf & _CMD_OPERATION:
                                    ts_dec.read_amf3_value()

                        if ts_dec.remaining() == 0:
                            # Perfect match — compute body end
                            # Body end = timestamp position minus pre-timestamp fields
                            # We need to find where the fields between body and timestamp start
                            # For now, if no fields between body and timestamp, body ends at i
                            if pre_ts_fields == 0:
                                return i
                            # Otherwise scan back for pre-timestamp fields
                            # This is complex; for typical DSK responses (body + timestamp + bytes)
                            # there are no clientId/destination/headers/messageId inline
                            return i
                    except:
                        continue
            except:
                continue
        return None

    # --- Envelope ---

    def read_amf_envelope(self):
        """Read full AMF envelope: version, headers, bodies."""
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
            # Reset AMF3 refs per body
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
        # AMF3 tables
        self.string_table = []
        self.object_table = []
        self.trait_table = []

    def get_bytes(self):
        return bytes(self.buf)

    def write_u8(self, v):
        self.buf.append(v & 0xFF)

    def write_u16(self, v):
        self.buf += _struct.pack('>H', v)

    def write_u32(self, v):
        self.buf += _struct.pack('>I', v)

    def write_i32(self, v):
        self.buf += _struct.pack('>i', v)

    def write_double(self, v):
        self.buf += _struct.pack('>d', v)

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
            self.write_amf3_u29(1)  # empty string, inline, length 0
            return
        if s in self.string_table:
            idx = self.string_table.index(s)
            self.write_amf3_u29(idx << 1)  # reference
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
            self.write_amf3_string("")  # empty assoc terminator
            for item in val:
                self.write_amf3_value(item)

        elif isinstance(val, dict):
            amf_type = val.get("__amf_type", "")

            if amf_type == "undefined":
                self.write_u8(AMF3_UNDEFINED)

            elif amf_type == "date":
                self.write_u8(AMF3_DATE)
                self.write_amf3_u29(1)  # inline
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
                self.write_amf3_string("")  # terminator
                for item in dense:
                    self.write_amf3_value(item)

            elif amf_type == "object":
                self._write_amf3_object(val)

            elif amf_type in ("amf0_object", "amf0_typed", "amf0_ecma_array"):
                # Re-encode as AMF3 object (will be wrapped in AMF0_AMF3 at body level)
                self._write_amf3_object(val)

            elif amf_type in ("amf0_date",):
                self.write_u8(AMF3_DATE)
                self.write_amf3_u29(1)
                self.write_double(val.get("ms", 0.0))

            elif amf_type in ("amf0_xml",):
                self.write_u8(AMF3_XML)
                xml_bytes = val.get("value", "").encode('utf-8')
                self.write_amf3_u29((len(xml_bytes) << 1) | 1)
                self.buf += xml_bytes

            else:
                # Generic dict -> AMF3 dynamic object
                self._write_amf3_object(val)

        else:
            self.write_u8(AMF3_NULL)

    def _write_amf3_object(self, obj):
        self.write_u8(AMF3_OBJECT)

        class_name = obj.get("__class", "")
        is_ext = obj.get("__externalizable", False)

        # Filter out metadata keys
        meta_keys = {"__amf_type", "__class", "__externalizable", "__raw_b64", "value"}
        if is_ext:
            data_keys = []
        else:
            data_keys = [k for k in obj.keys() if k not in meta_keys]

        # Check trait cache
        trait_key = (class_name, is_ext, tuple(data_keys))
        if trait_key in [(t[0], t[1], tuple(t[2])) for t in self.trait_table]:
            trait_idx = [(t[0], t[1], tuple(t[2])) for t in self.trait_table].index(trait_key)
            ref = (trait_idx << 2) | 1  # not inline traits, but inline object
            self.write_amf3_u29(ref)
        else:
            # Inline traits
            self.trait_table.append((class_name, is_ext, data_keys))
            dynamic = not is_ext and not class_name  # dynamic if anonymous
            member_count = 0 if (is_ext or dynamic) else len(data_keys)
            flags = 3  # inline object (bit 0) + inline traits (bit 1)
            if is_ext:
                flags |= 4  # externalizable
            if dynamic:
                flags |= 8  # dynamic
            flags |= (member_count << 4)
            self.write_amf3_u29(flags)
            self.write_amf3_string(class_name)

            if not is_ext and not dynamic:
                # Write sealed member names
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
            # Dynamic object: write values then terminator
            for k in data_keys:
                self.write_amf3_string(k)
                self.write_amf3_value(obj[k])
            self.write_amf3_string("")  # end dynamic
        else:
            # Sealed members: write values in order
            for k in data_keys:
                self.write_amf3_value(obj[k])

    def _write_blazeds_message_external(self, obj, cls):
        f0 = 0
        f1 = 0
        if "body" in obj: f0 |= _AM_BODY
        if "clientId" in obj: f0 |= _AM_CLIENT_ID
        if "destination" in obj: f0 |= _AM_DESTINATION
        if "headers" in obj: f0 |= _AM_HEADERS
        if "messageId" in obj: f0 |= _AM_MESSAGE_ID
        if "timestamp" in obj: f0 |= _AM_TIMESTAMP
        if "timeToLive" in obj: f0 |= _AM_TIME_TO_LIVE
        if "clientIdBytes" in obj: f1 |= _AM_CLIENT_ID_BYTES
        if "messageIdBytes" in obj: f1 |= _AM_MSG_ID_BYTES
        if f1: f0 |= _AM_HAS_NEXT
        self.write_u8(f0)
        if f1: self.write_u8(f1)
        if f0 & _AM_BODY: self.write_amf3_value(obj["body"])
        if f0 & _AM_CLIENT_ID: self.write_amf3_value(obj["clientId"])
        if f0 & _AM_DESTINATION: self.write_amf3_value(obj["destination"])
        if f0 & _AM_HEADERS: self.write_amf3_value(obj["headers"])
        if f0 & _AM_MESSAGE_ID: self.write_amf3_value(obj["messageId"])
        if f0 & _AM_TIMESTAMP: self.write_amf3_value(obj["timestamp"])
        if f0 & _AM_TIME_TO_LIVE: self.write_amf3_value(obj["timeToLive"])
        if f1 & _AM_CLIENT_ID_BYTES: self.write_amf3_value(obj["clientIdBytes"])
        if f1 & _AM_MSG_ID_BYTES: self.write_amf3_value(obj["messageIdBytes"])

        is_async = cls in ("flex.messaging.messages.AsyncMessage",
            "flex.messaging.messages.AsyncMessageExt",
            "flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage", "DSK", "DSA")
        is_ack = cls in ("flex.messaging.messages.AcknowledgeMessage",
            "flex.messaging.messages.AcknowledgeMessageExt",
            "flex.messaging.messages.ErrorMessage", "DSK")
        is_command = cls in ("flex.messaging.messages.CommandMessage",
            "flex.messaging.messages.CommandMessageExt", "DSC")

        if is_async:
            sf0 = 0
            if "correlationId" in obj: sf0 |= _ASYNC_CORRELATION_ID
            if "correlationIdBytes" in obj: sf0 |= _ASYNC_CORRELATION_ID_BYTES
            self.write_u8(sf0)
            if sf0 & _ASYNC_CORRELATION_ID: self.write_amf3_value(obj["correlationId"])
            if sf0 & _ASYNC_CORRELATION_ID_BYTES: self.write_amf3_value(obj["correlationIdBytes"])
            if is_ack:
                self.write_u8(0)
                if cls == "flex.messaging.messages.ErrorMessage":
                    ef0 = 0
                    if "extendedData" in obj: ef0 |= 0x01
                    if "faultCode" in obj: ef0 |= 0x02
                    if "faultDetail" in obj: ef0 |= 0x04
                    if "faultString" in obj: ef0 |= 0x08
                    if "rootCause" in obj: ef0 |= 0x10
                    self.write_u8(ef0)
                    if ef0 & 0x01: self.write_amf3_value(obj["extendedData"])
                    if ef0 & 0x02: self.write_amf3_value(obj["faultCode"])
                    if ef0 & 0x04: self.write_amf3_value(obj["faultDetail"])
                    if ef0 & 0x08: self.write_amf3_value(obj["faultString"])
                    if ef0 & 0x10: self.write_amf3_value(obj["rootCause"])
        elif is_command:
            sf0 = 0
            if "operation" in obj: sf0 |= _CMD_OPERATION
            self.write_u8(sf0)
            if sf0 & _CMD_OPERATION: self.write_amf3_value(obj["operation"])

    def write_amf0_value(self, val):
        """Write a value in AMF0 format, switching to AMF3 for complex types."""
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
            # Switch to AMF3
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
                self.buf += _struct.pack('>h', val.get("tz", 0))
            elif amf_type == "amf0_xml":
                self.write_u8(AMF0_XML)
                self.write_amf0_long_utf8(val.get("value", ""))
            elif amf_type == "amf0_unknown":
                # Re-emit original marker + raw
                self.write_u8(val.get("marker", 0))
                self.buf += base64.b64decode(val.get("raw_b64", ""))
            else:
                # AMF3-style objects — switch to AMF3
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
            # Write body to temp encoder to get length
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
            # Reset AMF3 refs per body
            self.string_table = []
            self.object_table = []
            self.trait_table = []
            # Write body to temp encoder to get length
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
    # AMF version 0 or 3
    version = _struct.unpack('>H', body_bytes[:2])[0]
    if version not in (0, 3):
        return False
    # Header count should be reasonable
    header_count = _struct.unpack('>H', body_bytes[2:4])[0]
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

    SUMMARY_THRESHOLD = 512 * 1024

    def transform_response_decode(self, body, headers):
        try:
            dec = AMFDecoder(body)
            envelope = dec.read_amf_envelope()

            # Always embed original AMF binary for lossless restore
            envelope["__amf_original_b64"] = base64.b64encode(body).decode()
            json_str = json.dumps(envelope, indent=2, ensure_ascii=False, default=str)

            if len(json_str) > self.SUMMARY_THRESHOLD:
                import time as _time
                import tempfile as _tempfile
                save_dir = os.path.join(_tempfile.gettempdir(), 'amf_responses')
                os.makedirs(save_dir, exist_ok=True)
                ts = _time.strftime('%Y%m%d_%H%M%S')
                filepath = os.path.join(save_dir, 'resp_%s.json' % ts)
                rawpath = os.path.join(save_dir, 'resp_%s.amf' % ts)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                with open(rawpath, 'wb') as f:
                    f.write(body)

                summary = _build_response_summary(envelope, filepath)
                summary["__amf_raw_file"] = rawpath.replace('\\', '/')
                summary_str = json.dumps(summary, indent=2, ensure_ascii=False, default=str)
                new_body = summary_str.encode('utf-8')

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
        try:
            text = body.decode('utf-8', errors='replace')
            head = text[:200]

            # Case 1: Summary with raw AMF file
            if '__amf_summary' in head:
                obj = json.loads(text)
                raw_file = obj.get("__amf_raw_file", "")
                if raw_file and os.path.exists(raw_file):
                    with open(raw_file, 'rb') as f:
                        amf_body = f.read()
                    print("[Plugin:AMF] Response restored from file (%d bytes)" % len(amf_body))
                    return amf_body, {'Content-Type': 'application/x-amf'}

            # Case 2: JSON with embedded original AMF
            if '__amf_original_b64' in text:
                obj = json.loads(text)
                if "__amf_original_b64" in obj:
                    amf_body = base64.b64decode(obj["__amf_original_b64"])
                    print("[Plugin:AMF] Response restored from original (%d bytes)" % len(amf_body))
                    return amf_body, {'Content-Type': 'application/x-amf'}

            # Case 3: Normal JSON → AMF re-encode (no original available)
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


# --- Response Summary Helpers (shared with module version) ---

def _human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return "%.1f%s" % (n, unit)
        n /= 1024
    return "%.1fTB" % n


def _flatten_record(record):
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
    if isinstance(obj, dict):
        count = 1 if "__raw_b64" in obj else 0
        for v in obj.values():
            count += _count_raw_b64(v)
        return count
    if isinstance(obj, list):
        return sum(_count_raw_b64(item) for item in obj)
    return 0


def _build_response_summary(envelope, filepath):
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
        records_found = _find_records(value)
        if records_found:
            path, arr = records_found[0]
            summary["record_path"] = path
            summary["record_count"] = len(arr)
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
        "python amesianx_proxy.py --amf-decode %s --list" % fp,
        "python amesianx_proxy.py --amf-decode %s --list --limit 100" % fp,
        "python amesianx_proxy.py --amf-decode %s --list --search keyword" % fp,
        "python amesianx_proxy.py --amf-decode %s --list --deep" % fp,
        "python amesianx_proxy.py --amf-decode %s --json-dump" % fp,
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
        widths = {c: min(max(len(c), max((len(str(r.get(c, ""))) for r in flat_rows[:50]), default=0)), 20) for c in columns}
        hdr = " | ".join(c.ljust(widths[c])[:20] for c in columns)
        sep = "-+-".join("-" * min(widths[c], 20) for c in columns)
        print("  " + hdr)
        print("  " + sep)
        for r in flat_rows[:max_rows]:
            row = " | ".join(str(r.get(c, "")).ljust(widths[c])[:20] for c in columns)
            print("  " + row)
        print("  " + sep)
        print("  (%d / %d shown)" % (min(max_rows, len(flat_rows)), len(arr)))


# ============================================================
# Section 3: CONNECT Tunnel Helper
# ============================================================

def tunnel_traffic(client_sock, remote_sock):
    """Bidirectional tunnel for CONNECT (HTTPS)"""
    sockets = [client_sock, remote_sock]
    try:
        while True:
            readable, _, errors = select.select(sockets, [], sockets, 30)
            if errors:
                break
            for s in readable:
                data = s.recv(8192)
                if not data:
                    return
                if s is client_sock:
                    remote_sock.sendall(data)
                else:
                    client_sock.sendall(data)
    except:
        pass
    finally:
        client_sock.close()
        remote_sock.close()


# ============================================================
# Section 4: InboundHandler (uses plugin loop)
# ============================================================

class InboundHandler(http.server.BaseHTTPRequestHandler):
    burp_host = '127.0.0.1'
    burp_port = 8080
    protocol_version = 'HTTP/1.1'
    plugins = []

    def do_CONNECT(self):
        try:
            remote = socket.create_connection((self.burp_host, self.burp_port), timeout=10)
            connect_req = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (self.path, self.path)
            remote.sendall(connect_req.encode())
            resp = remote.recv(4096)
            self.wfile.write(resp)
            self.wfile.flush()
            print("[IN] CONNECT tunnel: %s" % self.path)
            tunnel_traffic(self.connection, remote)
        except Exception as e:
            print("[IN] CONNECT error: %s" % e)
            try:
                self.send_error(502)
            except:
                pass

    def _proxy_request(self, method):
        print("\n[IN] === REQUEST START ===")
        print("[IN] %s %s" % (method, self.path))
        print("[IN] Headers: %s" % dict(self.headers))

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except:
            content_length = 0
        print("[IN] Content-Length: %d" % content_length)

        try:
            body = self.rfile.read(content_length) if content_length > 0 else b''
        except Exception as e:
            print("[IN] ERROR reading body: %s" % e)
            traceback.print_exc()
            body = b''

        url = self.path
        print("[IN] Body read OK: %d bytes" % len(body))

        converted = False
        extra_headers = {}
        if body:
            for plugin in self.plugins:
                try:
                    if plugin.should_transform_inbound(body, dict(self.headers)):
                        body, extra_headers = plugin.transform_inbound(body, dict(self.headers))
                        converted = True
                        break
                except Exception as e:
                    print("[IN] Plugin %s error: %s" % (plugin.name, e))
                    traceback.print_exc()

        if not converted:
            if body:
                print("[IN] BYPASS (no plugin matched): %d bytes" % len(body))
            else:
                print("[IN] BYPASS (no body)")

        print("[IN] Forwarding to Burp %s:%d ..." % (self.burp_host, self.burp_port))
        try:
            conn = http.client.HTTPConnection(self.burp_host, self.burp_port, timeout=600)

            headers = {}
            for key, val in self.headers.items():
                lk = key.lower()
                if lk not in ('proxy-connection', 'proxy-authorization'):
                    headers[key] = val

            if converted:
                headers['Content-Length'] = str(len(body))

            for hk, hv in extra_headers.items():
                headers[hk] = hv

            conn.request(method, url, body=body, headers=headers)
            print("[IN] Waiting for Burp response...")
            resp = conn.getresponse()
            print("[IN] Burp responded: %d" % resp.status)

            resp_body = resp.read()
            resp_headers_dict = {k: v for k, v in resp.getheaders()}

            # Restore response (JSON -> AMF binary before sending to client)
            resp_extra = {}
            if resp_body:
                for plugin in self.plugins:
                    try:
                        if hasattr(plugin, 'transform_response_encode'):
                            resp_body, resp_extra = plugin.transform_response_encode(resp_body, resp_headers_dict)
                            if resp_extra:
                                break
                    except Exception as e:
                        print("[IN] Plugin %s response error: %s" % (plugin.name, e))
                        traceback.print_exc()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                lk = key.lower()
                if lk not in ('transfer-encoding', 'content-length', 'connection'):
                    if lk in [k.lower() for k in resp_extra]:
                        continue
                    self.send_header(key, val)
            for hk, hv in resp_extra.items():
                self.send_header(hk, hv)
            self.send_header('Content-Length', str(len(resp_body)))
            self.send_header('Connection', 'close')
            self.end_headers()

            self.wfile.write(resp_body)
            self.wfile.flush()
            conn.close()
            print("[IN] Response sent back to Fiddler: %d bytes" % len(resp_body))
            print("[IN] === REQUEST DONE ===")

        except ConnectionResetError:
            pass
        except ConnectionRefusedError:
            try:
                self.send_error(502)
            except:
                pass
        except OSError:
            pass
        except Exception as e:
            print("[IN] !!! Forward error: %s" % e)
            try:
                self.send_error(502, str(e))
            except:
                pass

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        self._proxy_request('POST')

    def do_PUT(self):
        self._proxy_request('PUT')

    def do_HEAD(self):
        self._proxy_request('HEAD')

    def do_OPTIONS(self):
        self._proxy_request('OPTIONS')

    def do_DELETE(self):
        self._proxy_request('DELETE')

    def log_message(self, format, *args):
        pass


# ============================================================
# Section 5: OutboundHandler (uses plugin loop, Host header port fallback)
# ============================================================

class OutboundHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    upstream_host = None  # e.g. '127.0.0.1'
    upstream_port = None  # e.g. 8888
    plugins = []

    def do_CONNECT(self):
        try:
            if self.upstream_host:
                # CONNECT through upstream proxy (Fiddler)
                remote = socket.create_connection((self.upstream_host, self.upstream_port), timeout=10)
                connect_req = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (self.path, self.path)
                remote.sendall(connect_req.encode())
                resp = remote.recv(4096)
                self.wfile.write(resp)
                self.wfile.flush()
                print("[OUT] CONNECT tunnel via upstream: %s" % self.path)
            else:
                host, port = self.path.split(':')
                port = int(port)
                remote = socket.create_connection((host, port), timeout=10)
                self.send_response(200, 'Connection Established')
                self.end_headers()
                print("[OUT] CONNECT tunnel direct: %s" % self.path)
            tunnel_traffic(self.connection, remote)
        except Exception as e:
            print("[OUT] CONNECT error: %s" % e)
            try:
                self.send_error(502)
            except:
                pass

    def _proxy_request(self, method):
        print("\n[OUT] === REQUEST START ===")
        print("[OUT] %s %s" % (method, self.path))
        print("[OUT] Headers: %s" % dict(self.headers))

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except:
            content_length = 0

        try:
            body = self.rfile.read(content_length) if content_length > 0 else b''
        except Exception as e:
            print("[OUT] ERROR reading body: %s" % e)
            traceback.print_exc()
            body = b''

        url = self.path
        parsed = urllib.parse.urlparse(url)
        # Host header port fallback (Burp may strip port from URL)
        host_header = self.headers.get('Host', '')
        if ':' in host_header:
            hh_host, hh_port = host_header.rsplit(':', 1)
            try:
                hh_port = int(hh_port)
            except:
                hh_host = host_header
                hh_port = None
        else:
            hh_host = host_header
            hh_port = None

        # 들어온 연결이 TLS면 원래 HTTPS 트래픽 → 기본 포트 443
        inbound_is_tls = hasattr(self.connection, 'getpeercert')  # SSL-wrapped socket
        default_port = 443 if (parsed.scheme == 'https' or inbound_is_tls) else 80

        target_host = parsed.hostname or hh_host
        target_port = parsed.port or hh_port or default_port
        path = parsed.path
        if parsed.query:
            path += '?' + parsed.query

        print("[OUT] Target: %s:%d%s" % (target_host, target_port, path))
        print("[OUT] Body: %d bytes" % len(body))

        converted = False
        extra_headers = {}
        if body:
            for plugin in self.plugins:
                try:
                    if plugin.should_transform_outbound(body, dict(self.headers)):
                        body, extra_headers = plugin.transform_outbound(body, dict(self.headers))
                        converted = True
                        break
                except Exception as e:
                    print("[OUT] Plugin %s error: %s" % (plugin.name, e))
                    traceback.print_exc()

        if not converted:
            if body:
                print("[OUT] BYPASS (no plugin matched): %d bytes" % len(body))
            else:
                print("[OUT] BYPASS (no body)")

        use_upstream = self.upstream_host is not None

        if use_upstream:
            print("[OUT] Connecting via upstream %s:%d to %s:%d ..." % (self.upstream_host, self.upstream_port, target_host, target_port))
        else:
            print("[OUT] Connecting to target %s:%d ..." % (target_host, target_port))
        try:
            if use_upstream:
                # Send through upstream proxy (Fiddler) - use full URL
                conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=600)
                request_path = url  # full URL for proxy request
            else:
                use_tls = parsed.scheme == 'https' or inbound_is_tls
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(target_host, target_port, timeout=600, context=ctx)
                else:
                    conn = http.client.HTTPConnection(target_host, target_port, timeout=600)
                request_path = path

            headers = {}
            for key, val in self.headers.items():
                lk = key.lower()
                if lk not in ('proxy-connection', 'proxy-authorization',
                              'x-ssv-converted', 'x-original-target'):
                    headers[key] = val

            if converted:
                headers['Content-Length'] = str(len(body))

            for hk, hv in extra_headers.items():
                headers[hk] = hv

            conn.request(method, request_path, body=body, headers=headers)
            print("[OUT] Waiting for target response...")
            resp = conn.getresponse()
            print("[OUT] Target responded: %d" % resp.status)

            resp_body = resp.read()
            resp_headers_dict = {k: v for k, v in resp.getheaders()}

            # Transform response (AMF binary -> JSON for Burp viewing)
            resp_extra = {}
            if resp_body:
                for plugin in self.plugins:
                    try:
                        if plugin.should_transform_response(resp_body, resp_headers_dict):
                            resp_body, resp_extra = plugin.transform_response_decode(resp_body, resp_headers_dict)
                            break
                    except Exception as e:
                        print("[OUT] Plugin %s response error: %s" % (plugin.name, e))
                        traceback.print_exc()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                lk = key.lower()
                if lk not in ('transfer-encoding', 'content-length', 'connection'):
                    if lk in [k.lower() for k in resp_extra]:
                        continue
                    self.send_header(key, val)
            for hk, hv in resp_extra.items():
                self.send_header(hk, hv)
            self.send_header('Content-Length', str(len(resp_body)))
            self.send_header('Connection', 'close')
            self.end_headers()

            self.wfile.write(resp_body)
            self.wfile.flush()
            conn.close()
            print("[OUT] Response sent back to Burp: %d bytes" % len(resp_body))
            print("[OUT] === REQUEST DONE ===")

        except ConnectionResetError:
            pass
        except ConnectionRefusedError:
            try:
                self.send_error(502)
            except:
                pass
        except OSError:
            pass
        except Exception as e:
            print("[OUT] !!! Forward error: %s" % e)
            try:
                self.send_error(502, str(e))
            except:
                pass

    def do_GET(self):
        self._proxy_request('GET')

    def do_POST(self):
        self._proxy_request('POST')

    def do_PUT(self):
        self._proxy_request('PUT')

    def do_HEAD(self):
        self._proxy_request('HEAD')

    def do_OPTIONS(self):
        self._proxy_request('OPTIONS')

    def do_DELETE(self):
        self._proxy_request('DELETE')

    def log_message(self, format, *args):
        pass


# ============================================================
# Section 6: DualStackHTTPServer (auto-detect TLS via peek)
# ============================================================

class DualStackHTTPServer(http.server.HTTPServer):
    """HTTP server that auto-detects TLS or plain HTTP per connection"""

    def __init__(self, server_address, RequestHandlerClass, certfile=None, keyfile=None):
        super().__init__(server_address, RequestHandlerClass)
        self.certfile = certfile
        self.keyfile = keyfile
        if certfile and keyfile:
            self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_ctx.load_cert_chain(certfile, keyfile)
        else:
            self.ssl_ctx = None

    def get_request(self):
        client_socket, addr = self.socket.accept()
        if self.ssl_ctx:
            # Peek first bytes to detect TLS ClientHello (starts with 0x16)
            try:
                peek = client_socket.recv(1, socket.MSG_PEEK)
                if peek and peek[0] == 0x16:
                    # TLS handshake
                    client_socket = self.ssl_ctx.wrap_socket(client_socket, server_side=True)
            except Exception as e:
                print("[OUT] TLS peek/wrap error: %s" % e)
        return client_socket, addr


# ============================================================
# Section 7: Certificate Management (embedded default, --gen-cert fallback)
# ============================================================

def write_embedded_cert():
    """Write embedded PEM cert/key to temp files and return (certfile, keyfile) paths."""
    cert_dir = tempfile.mkdtemp(prefix="amesianx_proxy_")
    cert_path = os.path.join(cert_dir, "proxy.crt")
    key_path = os.path.join(cert_dir, "proxy.key")

    with open(cert_path, "w") as f:
        f.write(EMBEDDED_CERT_PEM)
    with open(key_path, "w") as f:
        f.write(EMBEDDED_KEY_PEM)

    return cert_path, key_path


def generate_cert_openssl():
    """Generate a fresh self-signed cert via openssl CLI, return (certfile, keyfile) paths."""
    cert_dir = tempfile.mkdtemp(prefix="amesianx_proxy_")
    cert_path = os.path.join(cert_dir, "proxy.crt")
    key_path = os.path.join(cert_dir, "proxy.key")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "36500", "-nodes",
        "-subj", "/CN=AmesianxProxy",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)

    return cert_path, key_path


# ============================================================
# Section 8: Main + CLI
# ============================================================

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
            env_bytes += _struct.pack('>H', len(target)) + target
            response = body.get("response", "").encode('utf-8')
            env_bytes += _struct.pack('>H', len(response)) + response
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
            env_bytes += _struct.pack('>i', len(amf_body))
            env_bytes += amf_body
            try:
                dec = AMFDecoder(bytes(env_bytes))
                new_envelope = dec.read_amf_envelope()
                body["value"] = new_envelope["bodies"][0]["value"]
            except Exception as e:
                print("[WARN] Deep decode failed for %s: %s" % (cls, e))
    return envelope


def _cli_amf_decode(args):
    """CLI mode: decode AMF response file."""
    with open(args.amf_decode, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    if '"amf_version"' in text[:500] or '"__amf_summary"' in text[:500]:
        json_start = text.index('{')
        envelope = json.loads(text[json_start:])
        if envelope.get("__amf_summary"):
            full_path = envelope.get("full_data_file", "")
            if full_path and os.path.exists(full_path):
                print("[*] Loading full data from: %s" % full_path)
                with open(full_path, 'r', encoding='utf-8') as f2:
                    envelope = json.loads(f2.read())
            else:
                print("[!] Full data not found: %s" % full_path)
                print(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
                return
        print("[*] Loaded JSON envelope")
    else:
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
            return

    if args.deep:
        raw_check = json.dumps(envelope, default=str)
        if '__raw_b64' in raw_check:
            print("[*] Deep parsing raw_b64 fields...")
            envelope = _deep_decode_raw_b64(envelope)

    if args.json_dump:
        envelope.pop("__amf_original_b64", None)
        print(json.dumps(envelope, indent=2, ensure_ascii=False, default=str))
        return

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


def main():
    parser = argparse.ArgumentParser(description='Amesianx Proxy — General-purpose proxy tool (red team edition)')
    parser.add_argument('--listen-in', type=int, default=8089,
                        help='Inbound port (Fiddler -> Proxy), default: 8089')
    parser.add_argument('--listen-out', type=int, default=8099,
                        help='Outbound port (Burp -> Proxy), default: 8099')
    parser.add_argument('--burp', type=int, default=8080,
                        help='Burp proxy port, default: 8080')
    parser.add_argument('--upstream', type=int, default=None,
                        help='Upstream proxy port for outbound (e.g. Fiddler 8888)')
    parser.add_argument('--no-nexacro', action='store_true',
                        help='Disable NexacroSSV plugin')
    parser.add_argument('--no-amf', action='store_true',
                        help='Disable AMF plugin')
    parser.add_argument('--raw-response', action='store_true',
                        help='Do not decode AMF responses (show raw binary in Burp)')
    parser.add_argument('--gen-cert', action='store_true',
                        help='Generate fresh self-signed cert via openssl CLI instead of using embedded cert')
    parser.add_argument('--amf-decode', type=str, metavar='FILE',
                        help='Decode AMF response file (CLI analysis mode)')
    parser.add_argument('--list', action='store_true',
                        help='(with --amf-decode) Show records as table')
    parser.add_argument('--limit', type=int, default=50,
                        help='(with --amf-decode) Max rows (default 50)')
    parser.add_argument('--search', type=str, default=None,
                        help='(with --amf-decode) Filter rows containing text')
    parser.add_argument('--deep', action='store_true',
                        help='(with --amf-decode) Deep parse raw_b64 fields')
    parser.add_argument('--json-dump', action='store_true',
                        help='(with --amf-decode) Full JSON dump')
    args = parser.parse_args()

    if args.amf_decode:
        _cli_amf_decode(args)
        return

    # Build plugin list
    active_plugins = []
    if not args.no_amf:
        active_plugins.append(AMFPlugin(decode_response=not args.raw_response))
    if not args.no_nexacro:
        active_plugins.append(NexacroSSVPlugin(decode_response=not args.raw_response))

    plugin_names = [p.name for p in active_plugins] if active_plugins else ["(none)"]

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        def handle_error(self, request, client_address):
            pass

    class ThreadedDualStackServer(socketserver.ThreadingMixIn, DualStackHTTPServer):
        daemon_threads = True
        def handle_error(self, request, client_address):
            pass

    InboundHandler.burp_host = '127.0.0.1'
    InboundHandler.burp_port = args.burp
    InboundHandler.plugins = active_plugins

    OutboundHandler.plugins = active_plugins
    if args.upstream:
        OutboundHandler.upstream_host = '127.0.0.1'
        OutboundHandler.upstream_port = args.upstream

    # Certificate setup
    if args.gen_cert:
        print("[*] Generating fresh self-signed certificate via openssl CLI...")
        cert_path, key_path = generate_cert_openssl()
    else:
        print("[*] Using embedded self-signed certificate for Proxy-OUT TLS...")
        cert_path, key_path = write_embedded_cert()
    print("[*] Cert: %s" % cert_path)

    in_server = ThreadedHTTPServer(('127.0.0.1', args.listen_in), InboundHandler)
    out_server = ThreadedDualStackServer(('127.0.0.1', args.listen_out), OutboundHandler,
                                         certfile=cert_path, keyfile=key_path)

    upstream_info = "127.0.0.1:%d (Fiddler)" % args.upstream if args.upstream else "DIRECT"

    banner = """
============================================================
  Amesianx Proxy — General-purpose proxy (red team edition)
============================================================

  Active Plugins: %s

  [Inbound]  127.0.0.1:%d  (Fiddler -> here, plugin transform)
  [Burp]     127.0.0.1:%d       (editing)
  [Outbound] 127.0.0.1:%d  (Burp -> here, plugin reverse -> %s) [HTTP+TLS]

  Fiddler Setup:
    Tools > Options > Gateway > Manual Proxy: 127.0.0.1:%d

  Burp Setup:
    1. Proxy Listener: 127.0.0.1:%d
    2. Settings > Network > Connections > Upstream Proxy:
       Destination: *  Proxy: 127.0.0.1  Port: %d

  * Plugin-matched requests -> transformed for editing in Burp
  * Non-matched requests -> bypassed as-is
  * Responses -> always bypassed as-is

  Press Ctrl+C to stop.
============================================================
""" % (', '.join(plugin_names),
       args.listen_in, args.burp, args.listen_out, upstream_info,
       args.listen_in, args.burp, args.listen_out)

    print(banner)

    in_thread = threading.Thread(target=in_server.serve_forever, daemon=True)
    out_thread = threading.Thread(target=out_server.serve_forever, daemon=True)

    in_thread.start()
    out_thread.start()

    try:
        while True:
            in_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        in_server.shutdown()
        out_server.shutdown()


if __name__ == '__main__':
    main()
