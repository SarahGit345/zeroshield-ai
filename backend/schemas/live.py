from typing import Literal

from pydantic import BaseModel


class LiveStepRequest(BaseModel):
    # Simulated analyst feedback: the dataset label is applied after the decision, as in the offline simulator.
    learn: bool = False
    attack_mode: Literal["default", "guarded", "gated"] = "default"
    # "template" keeps replay fast and reproducible; "configured" uses the configured LLM provider (slow on CPU).
    report: Literal["template", "configured"] = "template"
    count: int = 1
