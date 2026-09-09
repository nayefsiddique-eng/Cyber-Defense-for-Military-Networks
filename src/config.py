from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    # --- Deployment mode: 'lightweight' (asyncio + JSONL) or 'full' (Kafka + OpenSearch) ---
    MODE: str = 'lightweight'

    # --- Full-mode backends ---
    KAFKA_BROKERS: str = 'localhost:19092'
    OPENSEARCH_HOST: str = 'http://localhost:9200'

    # --- Paths ---
    SQLITE_DB_PATH: str = 'data/db/cyberdefense.db'
    TELEMETRY_OUTPUT_DIR: str = 'data/telemetry'
    PCAP_OUTPUT_DIR: str = 'data/pcaps'
    SCENARIO_DIR: str = 'data/scenarios'
    MODEL_DIR: str = 'data/models'
    DATASET_DIR: str = 'data/datasets'
    OUTPUT_DIR: str = 'data/output'

    # --- Determinism: all RNG streams derive from this via SHA-256 ---
    MASTER_SEED: int = 42

    LOG_LEVEL: str = 'INFO'
    API_HOST: str = '0.0.0.0'
    API_PORT: int = 8000

    # --- Pipeline tuning ---
    BATCH_SIZE: int = 1000
    FLUSH_INTERVAL_SECONDS: float = 2.0

    # --- Detection engine ---
    DETECTION_WINDOW_SECONDS: float = 300.0
    DETECTION_BASELINE_WINDOW_SECONDS: float = 3600.0
    DETECTION_ALERT_THRESHOLD: float = 0.40
    DETECTION_WEIGHT_RULE: float = 0.35
    DETECTION_WEIGHT_ANOMALY: float = 0.25
    DETECTION_WEIGHT_CLASSIFIER: float = 0.25
    DETECTION_WEIGHT_BEHAVIOUR: float = 0.15
    DETECTION_BATCH_SIZE: int = 64
    DETECTION_BATCH_TIMEOUT_MS: int = 250
    # Bound feature-store memory on long runs
    DETECTION_MAX_ENTITIES: int = 50000
    DETECTION_MIN_BASELINE_OBSERVATIONS: int = 5

    # --- Correlation ---
    CORRELATION_WINDOW_SECONDS: float = 1800.0

    model_config = SettingsConfigDict(
        env_prefix='CYBERDEF_',
        env_file='.env',
        extra='ignore'
    )


config = Config()
