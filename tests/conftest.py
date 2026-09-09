import pytest

from src.config import Config
from src.models.inventory import AssetInventory
from src.pipeline.event_bus import AsyncQueueBus
from src.simulator.engine import DeterministicPRNGManager
from src.simulator.topology import MilitaryTopologyBuilder


@pytest.fixture
def test_config(tmp_path):
    return Config(
        MODE='lightweight',
        SQLITE_DB_PATH=str(tmp_path / 'test.db'),
        TELEMETRY_OUTPUT_DIR=str(tmp_path / 'telemetry'),
        PCAP_OUTPUT_DIR=str(tmp_path / 'pcaps'),
        MODEL_DIR=str(tmp_path / 'models'),
        DATASET_DIR=str(tmp_path / 'datasets'),
        OUTPUT_DIR=str(tmp_path / 'output'),
        MASTER_SEED=1337,
    )


@pytest.fixture
def tmp_inventory(tmp_path):
    return AssetInventory(str(tmp_path / 'inventory.db'))


@pytest.fixture
def built_topology(tmp_inventory):
    MilitaryTopologyBuilder().build(tmp_inventory)
    return tmp_inventory


@pytest.fixture
def prng():
    return DeterministicPRNGManager(1337)


@pytest.fixture
async def event_bus():
    bus = AsyncQueueBus()
    await bus.start()
    try:
        yield bus
    finally:
        await bus.stop()
