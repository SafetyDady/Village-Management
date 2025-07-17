import os
from typing import List
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Database Configuration
    database_url: str = os.getenv("DATABASE_URL", "")
    db_host: str = os.getenv("DB_HOST", "")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "defaultdb")
    db_user: str = os.getenv("DB_USER", "")
    db_password: str = os.getenv("DB_PASSWORD", "")
    
    # Application Configuration
    app_name: str = os.getenv("APP_NAME", "Smart Village Management API")
    app_version: str = os.getenv("APP_VERSION", "1.0.0")
    debug: bool = os.getenv("DEBUG", "True").lower() == "true"
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    
    # CORS Configuration
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://wnhfnyob.manussite.space"
    ]
    
    @property
    def database_url_sync(self) -> str:
        """Get synchronous database URL"""
        if self.database_url:
            return self.database_url
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
    
    @property
    def database_url_async(self) -> str:
        """Get asynchronous database URL"""
        sync_url = self.database_url_sync
        return sync_url.replace("postgresql://", "postgresql+asyncpg://")

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()

