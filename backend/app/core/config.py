from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # --- Google AI Credentials & Models ---
    GOOGLE_API_KEY: str
    GEMINI_MODEL_NAME: str
    EMBEDDING_MODEL_NAME: str
    
    # --- Backend Security ---
    BACKEND_API_KEY: str

    # Configure the location of the .env file (one directory up from /backend)
    model_config = SettingsConfigDict(env_file="../.env", env_file_encoding='utf-8')

# Create a single, reusable instance for the rest of the application to use
settings = Settings()