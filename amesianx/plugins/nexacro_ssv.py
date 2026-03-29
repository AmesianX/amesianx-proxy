"""NexacroSSV plugin: SSV <-> XML transformation for Nexacro platform."""

import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

from .base import BodyTransformPlugin


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
        """SSV response -> XML (for viewing in Burp)."""
        try:
            xml_body = _ssv_to_xml(body)
            new_body = xml_body.encode('utf-8')
            print("[Plugin:NexacroSSV] Response SSV -> XML (%d -> %d bytes)" % (len(body), len(new_body)))
            return new_body, {'Content-Type': 'application/xml', 'X-SSV-Response-Converted': 'true'}
        except Exception as e:
            print("[Plugin:NexacroSSV] Response decode error: %s" % e)
            return body, {}

    def transform_response_encode(self, body, headers):
        """XML response -> SSV (restore before sending to client)."""
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
