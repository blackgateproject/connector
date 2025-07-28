from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    BLOCKCHAIN_RPC_URL: str
    BLOCKCHAIN_WALLET_PRVT_KEY: str
    BLOCKCHAIN_WALLET_ADDR: str
    SUPABASE_URL: str
    SUPABASE_AUTH_ANON_KEY: str
    SUPABASE_AUTH_SERV_KEY: str
    SUPABASE_AUTH_JWT_SECRET: str
    SUPABASE_JWT_ALGORITHM: str
    SUPABASE_JWT_EXPIRES: int
    SUPABASE_DB_URL: str
    DEBUG: int
    ZKSYNC_NODE_TYPE: str
    BLOCKCHAIN_CHAIN_ID: int
    CRED_SERVER_URL: str
    ACC_GENERATOR: int
    ACC_MODULUS: int

    # Redis Configuration for Multi-Worker Setup
    REDIS_URL: str = "redis://127.0.0.1:6379"

    # Multi-Worker Configuration
    MULTI_WORKER_MODE: bool = False
    WORKER_COUNT: int = 1
    WORKER_ID: Optional[str] = None
    BLOCKCHAIN_WORKERS: int = 3
    BLOCKCHAIN_BATCH_SIZE: int = 5
