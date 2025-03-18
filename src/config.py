from pydantic_settings import BaseSettings
from typing import Optional
from functools import lru_cache
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    # AWS Settings
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-west-2"

    # MongoDB Settings
    mongodb_uri: str = "mongodb://localhost:27017/"
    mongodb_db_name: str = "cloud_security_scanner"

    # Security Settings
    jwt_secret_key: str = ""
    encryption_key: str = ""

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug_mode: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = False
        env_file_encoding = 'utf-8'

@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance
    """
    return Settings()

# Create a global settings instance
settings = get_settings() 