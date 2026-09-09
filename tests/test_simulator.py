from src.pipeline.event_bus import AsyncQueueBus
from src.pipeline.schema import RAW_EVENT_TYPES
from src.pipeline.topic_manager import TOPIC_REGISTRY
from src.simulator.engine import CyberRangeSimulator
from src.simulator.topology import MilitaryTopologyBuilder

RAW_TOPICS = [f"telemetry.{t}" for t in RAW_EVENT_TYPES]


async def _simulate(config, seed=7, duration=600.0):
    bus = AsyncQueueBus()
    await bus.start()
    got = []
    await bus.subscribe(RAW_TOPICS, 'test', lambda t, k, v: got.append((t, k, v)))
    sim = CyberRangeSimulator(config, bus, seed=seed)
    await sim.start(duration_seconds=duration)
    assert await bus.drain(timeout=20.0)
    await bus.stop()
    return sim, got


def test_topology_builds_36_assets(built_topology):
    assets = built_topology.get_all()
    assert len(assets) == 36
    assert all(a.ip and a.hostname for a in assets)


def test_topology_build_is_idempotent(tmp_inventory):
    MilitaryTopologyBuilder().build(tmp_inventory)
    MilitaryTopologyBuilder().build(tmp_inventory)
    assert len(tmp_inventory.get_all()) == 36


def test_simulator_constructs(test_config):
    assert CyberRangeSimulator(test_config, None).seed == test_config.MASTER_SEED


def test_seed_override(test_config):
    assert CyberRangeSimulator(test_config, None, seed=99).seed == 99


async def test_publishes_every_event_losslessly(test_config):
    sim, got = await _simulate(test_config)
    assert sim.stats['events_generated'] > 0
    assert sim.stats['events_published'] == sim.stats['events_generated']
    assert len(got) == sim.stats['events_published']


async def test_only_registered_topics_are_used(test_config):
    _sim, got = await _simulate(test_config)
    topics = {t for t, _, _ in got}
    assert topics
    assert all(t in TOPIC_REGISTRY for t in topics)


async def test_payloads_carry_normalizer_keys(test_config):
    _sim, got = await _simulate(test_config)
    for _topic, key, value in got:
        assert 'event_id' in value and 'timestamp' in value
        assert key is not None, f"null partition key for {value.get('event_type')}"


async def test_login_events_fire_at_short_durations(test_config):
    _sim, got = await _simulate(test_config, duration=600.0)
    assert any(v.get('action') == 'login' for _t, _k, v in got)


async def test_simulation_is_deterministic(test_config):
    a, _ = await _simulate(test_config, seed=7, duration=300.0)
    b, _ = await _simulate(test_config, seed=7, duration=300.0)
    assert a.stats['events_by_type'] == b.stats['events_by_type']


async def test_different_seeds_diverge(test_config):
    a, _ = await _simulate(test_config, seed=7, duration=300.0)
    b, _ = await _simulate(test_config, seed=8, duration=300.0)
    assert a.stats['events_by_type'] != b.stats['events_by_type']
