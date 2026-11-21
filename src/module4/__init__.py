"""
src/module4
Package cho Tầng 4 (Validator & Scoped Patch Applier).
"""

from src.module4.patch_applier import (
    apply_patch_to_file,
    check_syntax_and_signature,
    extract_existing_imports,
    extract_method_signature,
    inject_imports,
)
from src.module4.schemas import PatchApplyResult, ValidationResult
from src.module4.validator import PatchValidator

__all__ = [
    "PatchValidator",
    "PatchApplyResult",
    "ValidationResult",
    "apply_patch_to_file",
    "check_syntax_and_signature",
    "extract_existing_imports",
    "extract_method_signature",
    "inject_imports",
]
