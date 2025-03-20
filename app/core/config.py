from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    BLOCKCHAIN_RPC_URL: str
    # ZK_HARDHAT_URL : str
    BLOCKCHAIN_WALLET_PRVT_KEY: str
    BLOCKCHAIN_WALLET_ADDR: str
    SUPABASE_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_SERV_KEY: str
    JWT_SECRET: str
    JWT_ALGORITHM: str
    JWT_EXPIRES: int
    DEBUG: int
    ZKSYNC_NODE_TYPE: str
    ZKSYNC_CHAIN_ID: int
    # BACKEND_DID: str
    # BACKEND_JWK: str
    # BACKEND_ACC: int
    # BACKEND_MODULUS: int
    # IPFS_SWARM_KEY: str
    # IPFS_API_URL: str
    # ENABLE_IPFS: bool
