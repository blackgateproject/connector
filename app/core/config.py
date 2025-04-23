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
    DEBUG: int
    ZKSYNC_NODE_TYPE: str
    BLOCKCHAIN_CHAIN_ID: int
    CRED_SERVER_URL: str
