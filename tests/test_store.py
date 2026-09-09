import json
from pathlib import Path

from src.pipeline.event_bus import AsyncQueueBus
from src.pipeline.store import JSONLFileStore, StorageSink

INDEX = 'telemetry.normalized.ocsf.auth'


async def test_jsonl_store_writes_batch(tmp_path):
    store = JSONLFileStore(output_dir=str(tmp_path))
    await store.start()
    await store.store_batch(INDEX, [{'a': 1}, {'a': 2}])
    await store.stop()

    lines = (tmp_path / 'telemetry-normalized-ocsf-auth.jsonl').read_text().splitlines()
    assert [json.loads(l)['a'] for l in lines] == [1, 2]


async def test_sink_flushes_partial_batch_on_stop(tmp_path):
    """Regression: stop() used to cancel the periodic flush mid-write, which
    created an empty file and dropped the entire buffered batch."""
    bus = AsyncQueueBus()
    store = JSONLFileStore(output_dir=str(tmp_path))
    # batch_size far above the event count, so only the shutdown flush can save it
    sink = StorageSink(bus, store, batch_size=10_000, flush_interval=0.2)

    await bus.start()
    await sink.start()
    for i in range(50):
        await bus.publish(INDEX, None, {'i': i})
    assert await bus.drain(timeout=10.0)
    await sink.stop()
    await bus.stop()

    assert sink.stats['events_stored'] == 50
    assert sink.stats['errors'] == 0
    lines = (tmp_path / 'telemetry-normalized-ocsf-auth.jsonl').read_text().splitlines()
    assert len(lines) == 50


async def test_sink_flushes_on_batch_size(tmp_path):
    bus = AsyncQueueBus()
    store = JSONLFileStore(output_dir=str(tmp_path))
    sink = StorageSink(bus, store, batch_size=10, flush_interval=60.0)

    await bus.start()
    await sink.start()
    for i in range(30):
        await bus.publish(INDEX, None, {'i': i})
    assert await bus.drain(timeout=10.0)
    await sink.stop()
    await bus.stop()

    assert sink.stats['events_stored'] == 30
    assert Path(tmp_path / 'telemetry-normalized-ocsf-auth.jsonl').exists()
