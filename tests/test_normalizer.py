from src.models.ocsf_schemas import SIM_EPOCH, severity_to_ocsf
from src.pipeline.normalizer import (
    ROUTES,
    TelemetryNormalizer,
    build_auth,
    build_finding,
    build_network,
    build_process,
)

NORMALIZED_TOPICS = sorted({r.dest_topic for r in ROUTES})


async def _normalize(event_bus, topic, raw):
    out = []
    await event_bus.subscribe(NORMALIZED_TOPICS, 'sink', lambda t, k, v: out.append((t, k, v)))
    n = TelemetryNormalizer(event_bus)
    await n.start()
    await event_bus.publish(topic, None, raw)
    assert await event_bus.drain()
    return n, out


def test_severity_mapping_inverts_scale():
    assert severity_to_ocsf(1) == 5
    assert severity_to_ocsf(3) == 3
    assert severity_to_ocsf(None) == 1


def test_auth_keeps_endpoints_and_event_code():
    e = build_auth({
        'event_id': 'E1', 'timestamp': 3600.0, 'src_ip': '10.10.1.55', 'src_port': 4444,
        'dst_ip': '10.10.1.10', 'username': 'admin', 'user_id': 'admin',
        'domain': 'MIL', 'logon_type': '3', 'event_code': 4625, 'hostname': 'WS01',
    })
    # All of these were dropped by the previous normalizer.
    assert e.event_id == 'E1'
    assert e.src_endpoint.ip == '10.10.1.55'
    assert e.dst_endpoint.ip == '10.10.1.10'
    assert e.event_code == 4625
    assert e.logon_type == '3'
    assert e.actor.user_name == 'admin'


def test_auth_status_inferred_from_event_code():
    assert build_auth({'timestamp': 0, 'event_code': 4625}).status == 'failure'
    assert build_auth({'timestamp': 0, 'event_code': 4624}).status == 'success'
    assert build_auth({'timestamp': 0, 'status': 'failure', 'event_code': 4624}).status == 'failure'


def test_sim_time_maps_to_real_clock():
    e = build_auth({'timestamp': 3600.0})
    assert e.sim_time == 3600.0
    assert e.time == SIM_EPOCH.replace(hour=1)
    assert e.time.hour == 1  # hour-of-day is meaningful, for login_time_deviation


def test_process_keeps_integrity_level():
    e = build_process({
        'timestamp': 1.0, 'process_name': 'cmd.exe', 'pid': 42,
        'integrity_level': 'High', 'parent_process_name': 'explorer.exe',
        'command_line': 'cmd /c whoami', 'hostname': 'WS01',
    })
    assert e.process.integrity_level == 'High'
    assert e.process.parent_name == 'explorer.exe'
    assert e.process.cmd_line == 'cmd /c whoami'
    assert e.device.hostname == 'WS01'


def test_finding_keeps_mitre_technique():
    e = build_finding({
        'timestamp': 1.0, 'signature': 'ET SCAN Nmap', 'signature_id': 2009582,
        'mitre_technique_id': 'T1046', 'severity': 1, 'src_ip': '10.0.0.9',
    })
    assert e.analytic_technique == 'T1046'
    assert e.signature_id == '2009582'
    assert e.severity_id == 5


def test_network_volumetrics_survive():
    e = build_network({'timestamp': 1.0, 'bytes_out': 5000, 'bytes_in': 10, 'packets_out': 7})
    assert (e.bytes_out, e.bytes_in, e.packets_out) == (5000, 10, 7)


def test_type_uid_is_serialized():
    e = build_auth({'timestamp': 0, 'status': 'success'})
    assert e.type_uid == e.class_uid * 100 + e.activity_id
    # A plain @property is dropped by model_dump, so type_uid never reached OCSF output.
    assert e.model_dump()['type_uid'] == 300201


async def test_routes_publish_to_normalized_topics(event_bus):
    n, out = await _normalize(event_bus, 'telemetry.raw.auth', {
        'event_id': 'E1', 'timestamp': 10.0, 'src_ip': '10.0.0.1',
        'username': 'u1', 'user_id': 'u1', 'event_code': 4624,
    })
    assert n.stats['events_normalized'] == 1
    assert n.stats['events_failed'] == 0
    assert len(out) == 1

    topic, key, payload = out[0]
    assert topic == 'telemetry.normalized.ocsf.auth'
    assert key == 'u1'
    assert payload['event_id'] == 'E1'
    assert payload['src_endpoint']['ip'] == '10.0.0.1'


async def test_unroutable_topic_is_not_counted_as_normalized(event_bus):
    n = TelemetryNormalizer(event_bus)
    await n._process_event('telemetry.raw.unknown', None, {'timestamp': 1.0})
    assert n.stats['events_normalized'] == 0
    assert n.stats['events_unroutable'] == 1


async def test_bad_payload_goes_to_dlq(event_bus):
    dlq = []
    await event_bus.subscribe(
        ['telemetry.dlq.validation_errors', 'telemetry.dlq.parsing_failures'],
        'dlq', lambda t, k, v: dlq.append(v),
    )
    n = TelemetryNormalizer(event_bus)
    await n.start()
    # src_port out of range fails Endpoint validation
    await event_bus.publish('telemetry.raw.dns', None, {'timestamp': 1.0, 'src_port': 999999})
    assert await event_bus.drain()

    assert n.stats['events_failed'] == 1
    assert n.stats['events_normalized'] == 0
    assert len(dlq) == 1
