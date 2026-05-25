from fastapi import FastAPI
from app.config import settings
app = FastAPI()

@app.get("/")
async def root():
    return settings.app_name
