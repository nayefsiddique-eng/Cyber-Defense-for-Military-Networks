"""Main CLI entry point for the Cyber Defense project."""

import argparse
import asyncio
import sys
import uvicorn
from typing import List, Optional

from src.config import config
from src.simulator.engine import CyberRangeSimulator
from src.pipeline.event_bus import create_event_bus
from src.pipeline.store import create_store, StorageSink
from src.pipeline.normalizer import TelemetryNormalizer
from src.pipeline.topic_manager import TopicManager


def start_api(host: str, port: int):
    """Start the FastAPI control plane."""
    print(f"Starting API server on {host}:{port} in {config.MODE} mode...")
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False)


async def run_pipeline():
    """Run the standalone streaming pipeline workers."""
    print(f"Starting pipeline workers in {config.MODE} mode...")
    
    event_bus = create_event_bus(mode=config.MODE)
    store = create_store(mode=config.MODE, output_dir=config.TELEMETRY_OUTPUT_DIR)

    if config.MODE == 'full':
        TopicManager.init_kafka_topics(config.KAFKA_BROKERS)
    else:
        TopicManager.init_lightweight_topics(event_bus)

    normalizer = TelemetryNormalizer(event_bus)
    sink = StorageSink(event_bus, store, config.BATCH_SIZE, config.FLUSH_INTERVAL_SECONDS)
    
    await event_bus.start()
    await store.start()
    await normalizer.start()
    await sink.start()
    
    print("Pipeline running. Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Stopping pipeline...")
    finally:
        await sink.stop()
        await normalizer.stop()
        await store.stop()
        await event_bus.stop()


async def run_detection(duration: float, seed: int, attack_scenarios: Optional[List[str]] = None,
                        show: int = 15):
    """Simulate, normalize and detect in one process, printing the alerts."""
    from src.detection.worker import ALERT_TOPIC, DetectionWorker

    print(f"Detecting over a {duration}s simulation (seed {seed})...")
    if attack_scenarios:
        print(f"Attack scenarios: {', '.join(attack_scenarios)}")

    event_bus = create_event_bus(mode=config.MODE)
    TopicManager.init_lightweight_topics(event_bus)
    normalizer = TelemetryNormalizer(event_bus)

    alerts = []
    await event_bus.start()
    await event_bus.subscribe([ALERT_TOPIC], 'alert_printer', lambda t, k, v: alerts.append(v))
    await normalizer.start()

    simulator = CyberRangeSimulator(config, event_bus, seed=seed)
    detector = DetectionWorker(event_bus, config, inventory=simulator.inventory)
    await detector.start()

    await simulator.start(duration_seconds=duration, attack_scenarios=attack_scenarios)
    await event_bus.drain(timeout=120.0)
    await detector.stop()
    await event_bus.drain(timeout=60.0)
    await normalizer.stop()
    await event_bus.stop()

    print(f"\nSimulator: {simulator.get_stats()}")
    print(f"Normalizer: {normalizer.stats}")
    print(f"Detection: {detector.stats}")

    by_type = {}
    for alert in alerts:
        by_type[alert['threat_type']] = by_type.get(alert['threat_type'], 0) + 1
    print(f"\n{len(alerts)} alerts by threat type: {by_type}")

    # Highest-scoring alert per (threat type, asset), so the sample shows the
    # range of detections rather than many near-identical rows.
    best = {}
    for alert in alerts:
        key = (alert['threat_type'], alert['asset_id'])
        if key not in best or alert['score'] > best[key]['score']:
            best[key] = alert

    for alert in sorted(best.values(), key=lambda a: -a['score'])[:show]:
        print(f"\n  [{alert['severity']:8s}] {alert['threat_type']}  "
              f"score={alert['score']:.2f} confidence={alert['confidence']:.2f}")
        print(f"    asset={alert['asset_id']} user={alert['user']} src={alert['source_ip']}")
        print(f"    {alert['evidence']}")


async def run_simulation(duration: float, seed: int, attack_scenarios: Optional[List[str]] = None):
    """Run the simulator with the full normalize + store pipeline attached."""
    print(f"Starting simulation for {duration}s with seed {seed}...")
    if attack_scenarios:
        print(f"Attack scenarios: {', '.join(attack_scenarios)}")

    event_bus = create_event_bus(mode=config.MODE)
    store = create_store(mode=config.MODE, output_dir=config.TELEMETRY_OUTPUT_DIR)

    if config.MODE == 'full':
        TopicManager.init_kafka_topics(config.KAFKA_BROKERS)
    else:
        TopicManager.init_lightweight_topics(event_bus)

    normalizer = TelemetryNormalizer(event_bus)
    sink = StorageSink(event_bus, store, config.BATCH_SIZE, config.FLUSH_INTERVAL_SECONDS)

    await event_bus.start()
    await normalizer.start()
    await sink.start()

    simulator = CyberRangeSimulator(config, event_bus, seed=seed)
    try:
        await simulator.start(duration_seconds=duration, attack_scenarios=attack_scenarios)
        if hasattr(event_bus, 'drain') and not await event_bus.drain(timeout=60.0):
            print("Warning: pipeline did not fully drain before shutdown.")
    except KeyboardInterrupt:
        print("Simulation interrupted.")
        await simulator.stop()
    finally:
        # Stop the sink before reporting so the final flush is counted.
        await sink.stop()
        await normalizer.stop()
        await event_bus.stop()

    print(f"Simulation completed: {simulator.get_stats()}")
    print(f"Normalizer: {normalizer.stats}")
    print(f"Storage: {sink.stats}")


def main():
    parser = argparse.ArgumentParser(description="Military Cyber Defense Range")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # API command
    api_parser = subparsers.add_parser("api", help="Start FastAPI control plane")
    api_parser.add_argument("--host", default=config.API_HOST, help="API bind host")
    api_parser.add_argument("--port", type=int, default=config.API_PORT, help="API bind port")
    
    # Simulator command
    sim_parser = subparsers.add_parser("simulate", help="Run cyber range simulator")
    sim_parser.add_argument("--duration", type=float, default=3600.0, help="Simulation duration (seconds)")
    sim_parser.add_argument("--seed", type=int, default=config.MASTER_SEED, help="Random seed")
    sim_parser.add_argument("--attacks", nargs="*", default=[],
                            help="Campaigns to run: apt_campaign, insider_threat, ransomware_precursor")
    
    # Detection command
    det_parser = subparsers.add_parser("detect", help="Simulate and run the detection engine")
    det_parser.add_argument("--duration", type=float, default=86400.0, help="Simulation duration (seconds)")
    det_parser.add_argument("--seed", type=int, default=config.MASTER_SEED, help="Random seed")
    det_parser.add_argument("--attacks", nargs="*",
                            default=["apt_campaign", "insider_threat", "ransomware_precursor"],
                            help="Campaigns to run")
    det_parser.add_argument("--show", type=int, default=15, help="Alerts to print")

    # Pipeline command
    pipe_parser = subparsers.add_parser("pipeline", help="Start standalone pipeline workers")
    
    args = parser.parse_args()
    
    if args.command == "api":
        start_api(args.host, args.port)
    elif args.command == "simulate":
        asyncio.run(run_simulation(args.duration, args.seed, args.attacks))
    elif args.command == "detect":
        asyncio.run(run_detection(args.duration, args.seed, args.attacks, args.show))
    elif args.command == "pipeline":
        asyncio.run(run_pipeline())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
