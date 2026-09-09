from src.pipeline.event_bus import AsyncQueueBus


async def test_consumer_groups_get_independent_delivery(event_bus):
    a, b = [], []
    await event_bus.subscribe(['t.x'], 'group_a', lambda t, k, v: a.append(v))
    await event_bus.subscribe(['t.x'], 'group_b', lambda t, k, v: b.append(v))

    for i in range(50):
        await event_bus.publish('t.x', str(i), {'i': i})
    assert await event_bus.drain()

    # Previously both groups shared one queue and stole each other's messages.
    assert len(a) == 50
    assert len(b) == 50


async def test_no_events_lost_under_load(event_bus):
    seen = []
    await event_bus.subscribe(['t.load'], 'g', lambda t, k, v: seen.append(v))

    for i in range(5000):
        await event_bus.publish('t.load', None, {'i': i})
    assert await event_bus.drain(timeout=20.0)

    assert len(seen) == 5000


async def test_publish_with_no_subscribers_is_dropped(event_bus):
    await event_bus.publish('t.nobody', None, {'i': 1})
    assert event_bus.get_topic_stats().get('t.nobody', 0) == 0


async def test_unsubscribe_stops_delivery(event_bus):
    seen = []
    await event_bus.subscribe(['t.u'], 'g', lambda t, k, v: seen.append(v))
    await event_bus.publish('t.u', None, {'i': 1})
    assert await event_bus.drain()

    await event_bus.unsubscribe('g')
    await event_bus.publish('t.u', None, {'i': 2})
    assert await event_bus.drain()

    assert seen == [{'i': 1}]


async def test_multiple_topics_one_group():
    bus = AsyncQueueBus()
    await bus.start()
    seen = []
    await bus.subscribe(['t.a', 't.b'], 'g', lambda t, k, v: seen.append((t, v)))

    await bus.publish('t.a', None, {'x': 1})
    await bus.publish('t.b', None, {'x': 2})
    assert await bus.drain()
    await bus.stop()

    assert sorted(t for t, _ in seen) == ['t.a', 't.b']
