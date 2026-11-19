"""
src/module3
Package cho Tầng 3 (Fixer Agent, Scoped Patch Applier, Validator & Fix-Validate Loop).
"""

from src.module3.fixer import FixerAgent
from src.module3.patch_applier import (
    apply_patch_to_file,
    check_syntax_and_signature,
    extract_existing_imports,
    extract_method_signature,
    inject_imports,
)
from src.module3.runner import FixLoopRunner, compute_fixer_metrics
from src.module3.schemas import (
    FixIterationResult,
    FixSummary,
    Module3Patch,
    PatchApplyResult,
    ValidationResult,
)
from src.module3.validator import PatchValidator

__all__ = [
    "FixerAgent",
    "PatchValidator",
    "FixLoopRunner",
    "compute_fixer_metrics",
    "Module3Patch",
    "PatchApplyResult",
    "ValidationResult",
    "FixIterationResult",
    "FixSummary",
    "apply_patch_to_file",
    "check_syntax_and_signature",
    "extract_existing_imports",
    "extract_method_signature",
    "inject_imports",
]
