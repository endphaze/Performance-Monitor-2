from pymongo import MongoClient
from core.config import settings

client = MongoClient(settings.db_uri)
db = client[settings.database_name]