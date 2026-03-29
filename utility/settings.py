from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "PerfMon2"
    admin_email: str
    items_per_user: int = 50

    class Config:
        env_file = ".env" # สามารถดึงค่าจากไฟล์ .env มาทับค่า default ได้

settings = Settings()
print(settings.app_name)