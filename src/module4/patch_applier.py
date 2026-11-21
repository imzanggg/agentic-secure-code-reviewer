"""
patch_applier.py
Áp dụng bản sửa cấp method (Method-Level Replacement) từ Fixer Agent vào file Java đầy đủ:
1. Trích xuất và chèn các import thực sự được dùng trong bản sửa (không trùng lặp).
2. Thay thế tất định đúng phạm vi method [context_start_line : context_end_line]
   và căn chỉnh thụt lề theo file gốc.
3. Kiểm tra nhanh cú pháp AST và bảo toàn chữ ký hàm bằng tree-sitter-java trước khi chạy Maven.
"""

import re
import textwrap
from pathlib import Path
from typing import List, Optional, Tuple

from tree_sitter import Language, Parser
import tree_sitter_java as tsjava

from src.module3.schemas import Module3Patch
from src.module4.schemas import PatchApplyResult
from src.schemas import Finding

_JAVA_LANGUAGE = Language(tsjava.language())
_TS_PARSER = Parser(_JAVA_LANGUAGE)

IMPORT_LINE_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;\s*$")
PACKAGE_LINE_RE = re.compile(r"^\s*package\s+[\w.]+\s*;\s*$")
VALID_IMPORT_RE = re.compile(r"^(?:static\s+)?[A-Za-z_][\w$]*(?:\.[A-Za-z_*][\w$]*)+$")
PLACEHOLDER_RE = re.compile(
    r"(?:^\s*\.\.\.\s*$"
    r"|//\s*\.\.\."
    r"|/\*\s*\.\.\.\s*\*/"
    r"|//\s*(?:rest\s+of|original|existing)\b[^\n]*(?:continues|unchanged|code|logic)"
    r"|//\s*unchanged\b)",
    re.IGNORECASE | re.MULTILINE,
)


def extract_existing_imports(file_path: str) -> str:
    """Đọc các dòng import hiện có ở đầu file Java."""
    path = Path(file_path)
    if not path.exists():
        return "// none"
    imports: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("import "):
            imports.append(stripped)
        elif re.match(r"^(?:public\s+|abstract\s+|final\s+)?(?:class|interface|enum)\s+", stripped):
            break
    return "\n".join(imports) if imports else "// none"


def inject_imports(
    source: str,
    required_imports: List[str],
    used_in_code: Optional[str] = None,
) -> Tuple[str, List[str]]:
    """Chèn các import mới vào đầu file Java (bỏ qua nếu đã tồn tại hoặc không xuất hiện trong code)."""
    if not required_imports:
        return source, []

    lines = source.splitlines()
    existing = set()
    last_import_idx = -1
    package_idx = -1

    for idx, line in enumerate(lines):
        m = IMPORT_LINE_RE.match(line)
        if m:
            existing.add(line.strip())
            last_import_idx = idx
        elif PACKAGE_LINE_RE.match(line):
            package_idx = idx
        elif re.match(r"^\s*(?:public\s+|abstract\s+|final\s+)?(?:class|interface|enum)\s+", line):
            break

    to_add: List[str] = []
    added_names: List[str] = []
    for raw in required_imports:
        clean = raw.strip()
        if not clean or clean.lower() == "none":
            continue
        if clean.startswith("import "):
            clean = clean[len("import "):].strip()
        if clean.endswith(";"):
            clean = clean[:-1].strip()
        if not VALID_IMPORT_RE.match(clean):
            continue

        # Bỏ qua các import thừa do LLM liệt kê nhưng thực tế không dùng (và không phải FQN trùng)
        if used_in_code is not None and not clean.endswith(".*"):
            simple_name = clean.rsplit(".", 1)[-1]
            if not re.search(rf"\b{re.escape(simple_name)}\b", used_in_code):
                continue
            if clean in used_in_code:
                continue

        stmt = f"import {clean};"
        if stmt not in existing and stmt not in to_add:
            to_add.append(stmt)
            added_names.append(clean)

    if not to_add:
        return source, []

    if last_import_idx >= 0:
        insert_at = last_import_idx + 1
    elif package_idx >= 0:
        insert_at = package_idx + 1
        to_add = [""] + to_add
    else:
        insert_at = 0

    new_lines = lines[:insert_at] + to_add + lines[insert_at:]
    trailing = "\n" if source.endswith("\n") else ""
    return "\n".join(new_lines) + trailing, added_names


def check_patch_preconditions(patch: Module3Patch) -> Optional[str]:
    """Kiểm tra tính hợp lệ sơ bộ của Patch trước khi thay thế method."""
    if patch.llm_error:
        return f"LLM call failed: {patch.llm_error}"
    if patch.parse_error:
        return f"Patch output failed parsing: {patch.parse_error}"
    if not patch.fixed_snippet.strip():
        return "<<<FIXED>>> block is empty."
    if PLACEHOLDER_RE.search(patch.fixed_snippet):
        return (
            "<<<FIXED>>> contains placeholder comments ('...' or '// rest of code'). "
            "Output the complete method without abbreviations."
        )
    return None


def _reindent_block(fixed_snippet: str, base_indent: str) -> List[str]:
    """Chuẩn hóa thụt lề tương đối của fixed_snippet rồi đặt theo base_indent của file gốc."""
    dedented = textwrap.dedent(fixed_snippet.strip("\n"))
    out: List[str] = []
    for line in dedented.splitlines():
        if line.strip():
            out.append(f"{base_indent}{line}")
        else:
            out.append("")
    return out


def apply_patch_to_file(finding: Finding, patch: Module3Patch) -> PatchApplyResult:
    """Thay thế tất định toàn bộ method [context_start_line : context_end_line] bằng fixed_snippet."""
    pre_err = check_patch_preconditions(patch)
    if pre_err:
        return PatchApplyResult(applied=False, strategy="failed", error=pre_err)

    target = Path(finding.file_path)
    if not target.exists():
        return PatchApplyResult(applied=False, strategy="failed", error=f"File not found: {finding.file_path}")

    raw_text = target.read_text(encoding="utf-8", errors="replace")
    file_lines = raw_text.splitlines()
    total_lines = len(file_lines)

    if not finding.context_start_line or not finding.context_end_line:
        return PatchApplyResult(
            applied=False,
            strategy="failed",
            error="Missing method AST bounds (context_start_line/context_end_line).",
        )

    start_line = finding.context_start_line
    end_line = finding.context_end_line
    if start_line < 1 or end_line > total_lines or start_line > end_line:
        return PatchApplyResult(
            applied=False,
            strategy="failed",
            error=f"Invalid method bounds {start_line}-{end_line} for file with {total_lines} lines.",
        )

    orig_slice = file_lines[start_line - 1 : end_line]
    orig_norm = textwrap.dedent("\n".join(orig_slice)).strip()
    fixed_norm = textwrap.dedent(patch.fixed_snippet).strip()
    if orig_norm == fixed_norm:
        return PatchApplyResult(
            applied=False,
            strategy="failed",
            error="<<<FIXED>>> method is identical to the original method (no change made).",
        )

    first_nonempty = next((l for l in orig_slice if l.strip()), orig_slice[0])
    base_indent = re.match(r"^[ \t]*", first_nonempty).group(0)
    replacement = _reindent_block(patch.fixed_snippet, base_indent)

    new_lines = file_lines[: start_line - 1] + replacement + file_lines[end_line:]
    trailing = "\n" if raw_text.endswith("\n") else ""
    patched_text = "\n".join(new_lines) + trailing

    final_text, added_imports = inject_imports(
        patched_text,
        patch.required_imports,
        used_in_code=patch.fixed_snippet,
    )
    line_shift = len(final_text.splitlines()) - len(patched_text.splitlines())

    target.write_text(final_text, encoding="utf-8")

    applied_start = start_line + line_shift
    applied_end = applied_start + max(len(replacement) - 1, 0)
    patch.line_start = applied_start
    patch.line_end = applied_end

    return PatchApplyResult(
        applied=True,
        strategy="exact",
        line_start=applied_start,
        line_end=applied_end,
        added_imports=added_imports,
    )


def _find_enclosing_method(node, target_line: int):
    if node.type == "method_declaration":
        s = node.start_point[0] + 1
        e = node.end_point[0] + 1
        if s <= target_line <= e:
            for ch in node.children:
                deeper = _find_enclosing_method(ch, target_line)
                if deeper is not None:
                    return deeper
            return node
    for ch in node.children:
        res = _find_enclosing_method(ch, target_line)
        if res is not None:
            return res
    return None


def extract_method_signature(file_path: str, target_line: int) -> Optional[str]:
    """Trích xuất phần header/signature của method chứa target_line (từ đầu method tới trước thân '{')."""
    path = Path(file_path)
    if not path.exists():
        return None
    data = path.read_bytes()
    tree = _TS_PARSER.parse(data)
    method_node = _find_enclosing_method(tree.root_node, target_line)
    if method_node is None:
        return None

    body_node = method_node.child_by_field_name("body")
    end_byte = body_node.start_byte if body_node is not None else method_node.end_byte
    sig_raw = data[method_node.start_byte : end_byte].decode("utf-8", errors="replace")
    return " ".join(sig_raw.split())


def check_syntax_and_signature(
    file_path: str,
    target_line: int,
    original_signature: Optional[str],
) -> Tuple[bool, bool, Optional[str]]:
    """
    Kiểm tra nhanh (~1ms) file sau khi vá bằng tree-sitter:
    - Cú pháp Java có hợp lệ không (not root.has_error)
    - Chữ ký method (tên, tham số, kiểu trả về, throws) có giữ nguyên không
    """
    path = Path(file_path)
    if not path.exists():
        return False, False, f"File not found: {file_path}"

    data = path.read_bytes()
    tree = _TS_PARSER.parse(data)
    if tree.root_node.has_error:
        return (
            False,
            False,
            "Tree-sitter detected Java syntax error (unbalanced braces, missing semicolon, or incomplete method).",
        )

    if original_signature is not None:
        new_sig = None
        for probe in range(target_line, target_line + 5):
            new_sig = extract_method_signature(file_path, probe)
            if new_sig is not None:
                break
        if new_sig is None:
            return (
                True,
                False,
                "Enclosing method could not be found after patching. Make sure <<<FIXED>>> includes the full method header and closing '}'.",
            )
        if new_sig != original_signature:
            return True, False, (
                f"Method signature was modified (not allowed). "
                f"Expected: '{original_signature}', Got: '{new_sig}'."
            )

    return True, True, None
