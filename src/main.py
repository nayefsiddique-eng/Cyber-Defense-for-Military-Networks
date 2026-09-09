"""Main CLI entry point for the Cyber Defense project."""

import argparse
import asyncio
import sys
import uvicorn
from typing import List

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


async def run_simulation(duration: float, seed: int):
    """Run the simulator with the full normalize + store pipeline attached."""
    print(f"Starting simulation for {duration}s with seed {seed}...")

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
        await simulator.start(duration_seconds=duration)
        if hasattr(event_bus, 'drain') and not await event_bus.drain(timeout=30.0):
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
    
    # Pipeline command
    pipe_parser = subparsers.add_parser("pipeline", help="Start standalone pipeline workers")
    
    args = parser.parse_args()
    
    if args.command == "api":
        start_api(args.host, args.port)
    elif args.command == "simulate":
        asyncio.run(run_simulation(args.duration, args.seed))
    elif args.command == "pipeline":
        asyncio.run(run_pipeline())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
