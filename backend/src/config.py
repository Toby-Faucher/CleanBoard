from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "CleanBoard"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    
    #TODO: this is temp
    database_url: Optional[str] = None
    secret_key: str = "your-secret-key-change-in-production"
    
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
