"""Deterministic, metadata-only resource bounds for Windows and Linux workers."""
from dataclasses import dataclass
from typing import Mapping
class ResourceValidationError(ValueError): pass
@dataclass(frozen=True)
class ResourceBudget:
    platform: str
    cpu_percent: int
    memory_mb: int
    runtime_seconds: int
    process_limit: int
    file_limit: int
    def __post_init__(self):
        if self.platform not in {"WINDOWS", "LINUX"}: raise ResourceValidationError("platform is unsupported")
        values=(self.cpu_percent,self.memory_mb,self.runtime_seconds,self.process_limit,self.file_limit)
        if any(not isinstance(v,int) or isinstance(v,bool) for v in values): raise ResourceValidationError("resource limits must be integers")
        if not 1 <= self.cpu_percent <= 100 or not 16 <= self.memory_mb <= 32768 or not 1 <= self.runtime_seconds <= 3600 or not 1 <= self.process_limit <= 128 or not 1 <= self.file_limit <= 10000: raise ResourceValidationError("resource limits are outside bounded policy")
DEFAULT_BUDGETS=(ResourceBudget("WINDOWS",50,1024,900,32,2000),ResourceBudget("LINUX",50,1024,900,32,2000))
def validate_cross_platform_budgets(budgets: tuple[ResourceBudget,...]=DEFAULT_BUDGETS) -> Mapping[str,ResourceBudget]:
    if not isinstance(budgets,tuple) or len(budgets)!=2: raise ResourceValidationError("both Windows and Linux budgets are required exactly once")
    if not all(isinstance(b,ResourceBudget) for b in budgets): raise ResourceValidationError("resource budget is invalid")
    if {b.platform for b in budgets}!={"WINDOWS","LINUX"}: raise ResourceValidationError("both Windows and Linux budgets are required exactly once")
    return {b.platform:b for b in budgets}
