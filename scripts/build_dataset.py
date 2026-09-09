"""Build a labelled train/test dataset from simulation runs.

Split is by held-out SEED, never by random row: feature vectors are windowed
and stateful, so rows from the same run share window state and a random split
would leak the test set into training.

  python scripts/build_dataset.py --train-seeds 1-8 --test-seeds 9-10
"""

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import config
from src.detection.features import FEATURE_NAMES
from src.detection.training import ALL_CAMPAIGNS, build_samples, summarise


def parse_seeds(text: str):
    if '-' in text:
        start, end = text.split('-', 1)
        return list(range(int(start), int(end) + 1))
    return [int(part) for part in text.split(',') if part]


def write_dataset(path: str, samples) -> None:
    payload = {
        'feature_names': list(FEATURE_NAMES),
        'rows': [s.row for s in samples],
        'labels': [s.label for s in samples],
        'entities': [s.entity for s in samples],
        'sim_times': [s.sim_time for s in samples],
        'event_ids': [s.event_id for s in samples],
        'techniques': [s.technique_id for s in samples],
        'campaigns': [s.campaign for s in samples],
    }
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--train-seeds', default='1-4')
    parser.add_argument('--test-seeds', default='5-6')
    parser.add_argument('--duration', type=float, default=86400.0,
                        help="Simulated seconds per run (1 day gives a real hour-of-day spread)")
    parser.add_argument('--attacks', nargs='*', default=ALL_CAMPAIGNS)
    args = parser.parse_args()

    for name, seeds in (('train', parse_seeds(args.train_seeds)),
                        ('test', parse_seeds(args.test_seeds))):
        print(f"\nBuilding {name} set from seeds {seeds}...")
        samples = await build_samples(config, seeds, args.duration, args.attacks)
        path = os.path.join(config.DATASET_DIR, f'{name}.json')
        write_dataset(path, samples)
        print(f"  {len(samples)} samples -> {path}")
        print(f"  class balance: {summarise(samples)}")


if __name__ == '__main__':
    asyncio.run(main())
