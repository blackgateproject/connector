from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    SUPABASE_URL: str 
    SUPABASE_ANON_KEY: str
    SUPABASE_SERV_KEY: str
    JWT_SECRET: str
    JWT_ALGORITHM: str
    JWT_EXPIRES: int
    HARDHAT_URL: str
    DEBUG: bool = False

