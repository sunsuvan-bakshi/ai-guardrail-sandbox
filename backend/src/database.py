"""
MongoDB Database Connection and Threat Logging module
Handles asynchronous/synchronous logging of guardrail scan results
"""

import os
import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Load MongoDB URI from environment variables or fallback to local MongoDB instance
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "ai_guardrail_db"
COLLECTION_NAME = "audit_logs"

class AuditLogger:
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS = 2000)
            # Trigger a ping to verify the connection
            self.client.admin.command('ping')
            self.db = self.client[DB_NAME]
            self.collection = self.db[COLLECTION_NAME]
            self.connected = True
        except ConnectionFailure:
            self.client = None
            self.db = None
            self.collection = None
            self.connected = False

    def log_event(self, prompt : str, analysis_result : dict) -> bool:
        """
        Logs a guardrail evaluation event and threat metadata to the MongoDB collection.
        """
        if not self.connected or self.collection is None:
            return False

        log_document = {
            "timestamp" : datetime.datetime.utcnow(),
            "prompt" : prompt,
            "is_safe" : analysis_result.get("is_safe"),
            "risk_score" : analysis_result.get("risk_score"),
            "matched_patterns" : analysis_result.get("matched_patterns", []),
            "reason" : analysis_result.get("reason")
        }

        try:
            self.collection.insert_one(log_document)
            return True
        except Exception as e:
            print(f"Failed to log event to MongoDB: {e}")
            return False

# Global instance for app usage across the backend
audit_logger = AuditLogger()