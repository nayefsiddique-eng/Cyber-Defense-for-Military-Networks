from pydantic_settings import BaseSettings, SettingsConfigDict

class Config(BaseSettings):
    MODE: str = 'lightweight'
    KAFKA_BROKERS: str = 'localhost:19092'
    OPENSEARCH_HOST: str = 'http://localhost:9200'
    SQLITE_DB_PATH: str = 'data/db/cyberdefense.db'
    TELEMETRY_OUTPUT_DIR: str = 'data/telemetry'
    PCAP_OUTPUT_DIR: str = 'data/pcaps'
    SCENARIO_DIR: str = 'data/scenarios'
    MASTER_SEED: int = 42
    LOG_LEVEL: str = 'INFO'
    API_HOST: str = '0.0.0.0'
    API_PORT: int = 8000
    BATCH_SIZE: int = 1000
    FLUSH_INTERVAL_SECONDS: float = 2.0

    model_config = SettingsConfigDict(
        env_prefix='CYBERDEF_',
        env_file='.env',
        extra='ignore'
    )

config = Config()
