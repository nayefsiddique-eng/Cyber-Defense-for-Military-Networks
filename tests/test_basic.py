import pytest
from src.config import config
from src.models.assets import AssetType, NetworkSegment

def test_config_defaults():
    assert config.MODE in ['lightweight', 'full']
    assert config.API_PORT == 8000

def test_enums():
    assert AssetType.WORKSTATION == "WORKSTATION"
    assert NetworkSegment.DMZ == "DMZ"
