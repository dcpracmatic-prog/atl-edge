"""
Versioned telemetry contracts (v1).
All producers and consumers must respect these models.
"""

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid


class AgentRegime(str, Enum):
    ESTABLE = "ESTABLE"
    INESTABLE = "INESTABLE"
    CONFLICTO = "CONFLICTO"


class ActionStrategy(str, Enum):
    DIRECT_EXECUTION = "DIRECT_EXECUTION"
    INTERCALAR_INTERVALOS = "INTERCALAR_INTERVALOS"
    REDUCIR_CONCURRENCIA = "REDUCIR_CONCURRENCIA"
    PARALELIZAR_EN_CHUNKS = "PARALELIZAR_EN_CHUNKS"
    MIGRAR_A_BATCH = "MIGRAR_A_BATCH"
    BLOQUEAR = "BLOQUEAR"
    QUARANTINE_AND_PERSUADE = "QUARANTINE_AND_PERSUADE"


class TelemetryEvent(BaseModel):
    """Only allowed input shape for the observer."""
    schema_version: str = Field(default="1.0", frozen=True)
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    agent_id: str
    task_name: str

    status_mask: int = Field(..., ge=0, description="64-bit agent status bitmask")
    payload_hash: int = Field(..., ge=0, description="64-bit payload / context hash")

    raw_logs: Optional[str] = Field(default=None, max_length=8192)
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    error_count: int = Field(default=0, ge=0)
    extra: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("status_mask", "payload_hash")
    @classmethod
    def fit_64bit(cls, v: int) -> int:
        return v & 0xFFFFFFFFFFFFFFFF


class FrictionObservation(BaseModel):
    """Sensor output."""
    event_id: str
    friction_score: float = Field(..., ge=0.0, le=1.0)
    smoothed_score: float = Field(..., ge=0.0, le=1.0)
    regime: AgentRegime
    jitter_factor: float = Field(..., ge=0.0)
    hist_n_used: int
    raw_bits: Optional[int] = None


class ReconfigurationPlan(BaseModel):
    """Controller output."""
    event_id: str
    strategy: ActionStrategy
    parameters: Dict[str, Any] = Field(default_factory=dict)
    reason: str
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class ImpactMeasurement(BaseModel):
    """Measurer output — closes the control loop."""
    event_id: str
    plan_id: str
    before_friction: float
    after_friction: float
    before_regime: AgentRegime
    after_regime: AgentRegime
    delta_friction: float
    success: bool
    notes: Optional[str] = None
