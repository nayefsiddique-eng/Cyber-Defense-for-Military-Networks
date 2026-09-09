"""Adapts attack-module output to the canonical RawEvent envelope.

The 11 attack modules use their own field names (dest_ip, proto, alert, sid).
Mapping them here keeps those modules readable and untouched, and gives one
place to change if the canonical schema evolves.
"""

from typing import Any, Dict

from src.pipeline.schema import RawEvent, RawEventData

# Attack event_type -> canonical event_type.
EVENT_TYPE_MAP = {'raw.network': 'raw.netflow'}

# Attack data key -> canonical key.
FIELD_MAP = {
    'dest_ip': 'dst_ip',
    'dest_port': 'dst_port',
    'proto': 'protocol',
    'user': 'username',
    'alert': 'signature',
    'sid': 'signature_id',
    'process': 'process_name',
    'parent_process': 'parent_process_name',
    'image_path': 'process_path',
    'query': 'query_name',
    'qtype': 'query_type',
    'rcode': 'response_code',
    # Attack modules put Windows/Sysmon Event IDs in data['event_id'].
    'event_id': 'event_code',
    'ticket_encryption_type': 'ticket_encryption',
}

# Vendor-specific detail with no canonical home; preserved for realism/export.
VENDOR_ONLY = {
    'conn_state', 'answers', 'service_name', 'service', 'sub_status',
    'share_name', 'privileges', 'dest_hostname',
}


def adapt(event: Dict[str, Any], event_id: str) -> RawEvent:
    event_type = EVENT_TYPE_MAP.get(event['event_type'], event['event_type'])

    data: Dict[str, Any] = {}
    vendor: Dict[str, Any] = {}
    for key, value in (event.get('data') or {}).items():
        if key in VENDOR_ONLY:
            vendor[key] = value
        else:
            data[FIELD_MAP.get(key, key)] = value

    if data.get('username') and not data.get('user_id'):
        data['user_id'] = data['username']
    if data.get('signature_id') is not None:
        data['signature_id'] = int(data['signature_id'])
    data['raw_vendor'] = vendor

    return RawEvent(
        event_id=event_id,
        timestamp=float(event['timestamp']),
        event_type=event_type,
        data=RawEventData(**data),
    )
