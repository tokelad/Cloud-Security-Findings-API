from pymongo import AsyncMongoClient
from app.config import settings

client = AsyncMongoClient(settings.mongodb_url)
db = client[settings.database_name]



