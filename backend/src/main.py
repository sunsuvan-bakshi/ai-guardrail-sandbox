"""
FastAPI Main Application Entrypoint.
Exposes security scanning endpoints and SOC telemetry data.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.guardrail import PromptGuardrail
from src.database import audit_logger

app = FastAPI(
    title = "AI Guardrail & Prompt Injection Detection API",
    version = "1.0.0",
    description = "MLSecOps security gateway for filtering LLM inputs in real-time."
)

# Initialize the Guardrail instance
guardrail_engine = PromptGuardrail(risk_threshold = 0.5)

class PromptRequest(BaseModel):
    prompt: str

@app.get("/health")
def health_check():
    """
    Health check endpoint verifying API and DB connection status.
    """
    return {
        "status" : "healthy",
        "database_connected" : audit_logger.connected
    }

@app.post("/inspect")
def inspect_prompt(payload : PromptRequest):
    """
    Inspects incoming prompts for prompt injections/jailbreaks, logs the telemetry event to MongoDB,
    and returns the evaluation.
    """
    try:
        # 1. Run deterministic guardrail heuristic scan
        result = guardrail_engine.analyze(payload.prompt)

        # 2. Log event to MongoDB audit trail
        audit_logger.log_event(payload.prompt, result)

        return {
            "success" : True,
            "data" : result
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = str(e))

@app.get("/logs")
def get_audit_logs(limit : int = 20):
    """Retrieve recent audit logs from MongoDB for the SOC dashboard."""
    if not audit_logger.connected or audit_logger.collection is None:
        return {
            "success" : False,
            "message" : "Database not connected.",
            "logs" : []
        }

    try:
        # Fetch recent logs sorted by timestamp descending
        logs = list(
            audit_logger.collection.find({}, {"_id" : 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return {
            "success" : True,
            "logs" : logs
        }

    except Exception as e:
        raise HTTPException(status_code = 500, detail = str(e))