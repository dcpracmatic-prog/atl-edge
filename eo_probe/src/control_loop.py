"""
Interfaces for the closed control loop.
"""

from abc import ABC, abstractmethod
from src.telemetry_schema import (
    TelemetryEvent,
    FrictionObservation,
    ReconfigurationPlan,
    ImpactMeasurement,
)


class Sensor(ABC):
    @abstractmethod
    def observe(self, event: TelemetryEvent) -> FrictionObservation:
        ...


class Controller(ABC):
    @abstractmethod
    def decide(self, observation: FrictionObservation, event: TelemetryEvent) -> ReconfigurationPlan:
        ...


class Actuator(ABC):
    @abstractmethod
    def act(self, plan: ReconfigurationPlan) -> str:
        """Apply the plan; return a plan_id."""
        ...


class Measurer(ABC):
    @abstractmethod
    def measure(
        self,
        plan_id: str,
        original_event: TelemetryEvent,
        before: FrictionObservation,
    ) -> ImpactMeasurement:
        ...
