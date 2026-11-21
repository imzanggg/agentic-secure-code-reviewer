"""
fixer.py
Fixer Agent (Tầng 3): nhận Finding + Verdict (kèm DataFlowTrace từ Reviewer)
và (từ vòng 2 trở đi) feedback sạch đã lọc FP từ Tầng 5,
sinh ra bản sửa cấp method (Method-Level Replacement).
"""

import re
import textwrap
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from src.agents.llm_client import LLMError
from src.module3.schemas import Module3Patch
from src.schemas import Finding, Verdict

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
EXPLANATION_RE = re.compile(
    r"EXPLANATION\s*:\s*(.+?)(?=\n\s*(?:IMPORTS\s*:|<<<FIXED(?:_METHOD)?>>>))",
    re.IGNORECASE | re.DOTALL,
)
IMPORTS_RE = re.compile(
    r"IMPORTS\s*:\s*(.+?)(?=\n\s*<<<FIXED(?:_METHOD)?>>>)",
    re.IGNORECASE | re.DOTALL,
)
FIXED_RE = re.compile(
    r"<<<FIXED(?:_METHOD)?>>>\s*\n?(.*?)\n?\s*<<<END_FIXED(?:_METHOD)?>>>",
    re.IGNORECASE | re.DOTALL,
)
MD_FENCE_START_RE = re.compile(r"^\s*```[a-zA-Z]*\s*\n?")
MD_FENCE_END_RE = re.compile(r"\n?\s*```\s*$")
FLAG_COMMENT_RE = re.compile(r"\s*//\s*<--\s*FLAGGED\b[^\n]*$", re.IGNORECASE | re.MULTILINE)
CLASS_DECL_RE = re.compile(r"^(?:public\s+|abstract\s+|final\s+)?(?:class|interface|enum)\s+")


def _strip_code_fences(block: str) -> str:
    cleaned = MD_FENCE_START_RE.sub("", block)
    cleaned = MD_FENCE_END_RE.sub("", cleaned)
    cleaned = FLAG_COMMENT_RE.sub("", cleaned)
    return cleaned.strip("\n")


def _parse_imports(raw_imports: str) -> List[str]:
    items: List[str] = []
    for line in raw_imports.splitlines():
        s = line.strip().lstrip("-*").strip()
        if not s or s.lower() == "none":
            continue
        if s.startswith("import "):
            s = s[len("import "):].strip()
        if s.endswith(";"):
            s = s[:-1].strip()
        if s:
            items.append(s)
    return items


def _extract_existing_imports(file_path: str) -> str:
    """Đọc các dòng import hiện có ở đầu file Java để đưa vào prompt."""
    path = Path(file_path)
    if not path.exists():
        return "// none"
    imports: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("import "):
            imports.append(stripped)
        elif CLASS_DECL_RE.match(stripped):
            break
    return "\n".join(imports) if imports else "// none"


def parse_fixer_output(
    text: str,
) -> Tuple[Optional[str], List[str], Optional[str], Optional[str]]:
    """
    Parse phản hồi text có cấu trúc từ Fixer LLM (Method-Level Replacement).
    Trả về: (explanation, required_imports, fixed_method, parse_error)
    """
    cleaned_text = THINK_BLOCK_RE.sub("", text).strip()

    fixed_m = FIXED_RE.search(cleaned_text)
    if not fixed_m:
        return None, [], None, "Missing required block: <<<FIXED>>>...<<<END_FIXED>>>"

    exp_m = EXPLANATION_RE.search(cleaned_text)
    explanation = " ".join(exp_m.group(1).split()) if exp_m else None

    imp_m = IMPORTS_RE.search(cleaned_text)
    imports = _parse_imports(imp_m.group(1)) if imp_m else []

    fixed_method = _strip_code_fences(fixed_m.group(1))
    if not fixed_method.strip():
        return explanation, imports, fixed_method, "Empty <<<FIXED>>> block"

    return explanation, imports, fixed_method, None


def _format_method_for_prompt(finding: Finding) -> str:
    """
    Chuẩn hóa thụt lề toàn bộ method về cột 0 để LLM dễ sao chép & sửa sạch,
    đồng thời đánh dấu dòng bị flag bằng `// <-- FLAGGED`.
    """
    start = finding.context_start_line or 1
    path = Path(finding.file_path)
    if path.exists() and finding.context_start_line and finding.context_end_line:
        all_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        raw_slice = all_lines[finding.context_start_line - 1 : finding.context_end_line]
        dedented_lines = textwrap.dedent("\n".join(raw_slice)).splitlines()
    else:
        dedented_lines = (finding.function_context or "").splitlines()

    annotated: List[str] = []
    for idx, line in enumerate(dedented_lines):
        actual_line = start + idx
        if finding.line_start <= actual_line <= finding.line_end:
            annotated.append(f"{line}  // <-- FLAGGED ({finding.cwe_id or finding.rule_id})")
        else:
            annotated.append(line)
    return "\n".join(annotated)


class FixerAgent:
    def __init__(
        self,
        client,
        prompt_dir: str = "configs/prompts",
        prompt_version: str = "fixer_v1",
        source_label: str = "local_llm",
    ):
        self.client = client
        self.prompt_version = prompt_version
        self.source_label = source_label

        base = Path(prompt_dir)
        self.system_prompt = (base / f"{prompt_version}_system.txt").read_text(encoding="utf-8")
        self.user_template = (base / f"{prompt_version}_user.txt").read_text(encoding="utf-8")

    def fix(
        self,
        finding: Finding,
        verdict: Optional[Verdict] = None,
        feedback: Optional[str] = None,
        iteration: int = 1,
        previous_fixed: Optional[str] = None,
    ) -> Module3Patch:
        if not finding.function_context:
            return self._fail_open(finding, iteration, parse_error="no_context")

        user_prompt = self._build_user_prompt(
            finding=finding,
            verdict=verdict,
            feedback=feedback,
            iteration=iteration,
            previous_fixed=previous_fixed,
        )

        try:
            resp = self.client.chat(self.system_prompt, user_prompt)
        except LLMError as e:
            print(f"[WARN] Fixer LLM error (finding={finding.finding_id}, iter={iteration}): {e}")
            return self._fail_open(finding, iteration, llm_error=str(e))

        thinking = getattr(resp, "thinking", None)
        if not resp.content.strip() and thinking:
            parse_err = (
                "Empty content: model spent tokens inside thinking trace "
                f"(done_reason={resp.done_reason}). Disable thinking (`think=False`) or increase num_predict."
            )
            print(f"[WARN] {parse_err}")
            return Module3Patch(
                finding_id=finding.finding_id,
                original_snippet=finding.function_context or "",
                fixed_snippet="",
                line_start=finding.context_start_line,
                line_end=finding.context_end_line,
                explanation=None,
                required_imports=[],
                parse_error=parse_err,
                llm_error=None,
                iteration=iteration,
                source="fail_open",
                model=resp.model,
                latency_sec=resp.latency_sec,
                prompt_tokens=resp.prompt_tokens,
                completion_tokens=resp.completion_tokens,
                raw_output=resp.content,
            )

        explanation, req_imports, fixed_method, parse_err = parse_fixer_output(resp.content)

        return Module3Patch(
            finding_id=finding.finding_id,
            original_snippet=finding.function_context or "",
            fixed_snippet=fixed_method or "",
            line_start=finding.context_start_line,
            line_end=finding.context_end_line,
            explanation=explanation,
            required_imports=req_imports,
            parse_error=parse_err,
            llm_error=None,
            iteration=iteration,
            source=self.source_label if not parse_err else "fail_open",
            model=resp.model,
            latency_sec=resp.latency_sec,
            prompt_tokens=resp.prompt_tokens,
            completion_tokens=resp.completion_tokens,
            raw_output=resp.content,
        )

    def fix_batch(
        self,
        findings: Iterable[Finding],
        verdicts_by_id: Optional[dict[str, Verdict]] = None,
    ) -> list[Module3Patch]:
        verdicts_by_id = verdicts_by_id or {}
        return [
            self.fix(f, verdict=verdicts_by_id.get(f.finding_id), iteration=1)
            for f in findings
        ]

    def _build_user_prompt(
        self,
        finding: Finding,
        verdict: Optional[Verdict],
        feedback: Optional[str],
        iteration: int,
        previous_fixed: Optional[str],
    ) -> str:
        method_code = _format_method_for_prompt(finding)

        if verdict and verdict.reasoning:
            reviewer_reasoning = verdict.reasoning.strip()
        else:
            reviewer_reasoning = finding.remediation_advice or finding.message

        if verdict and verdict.data_flow_trace:
            dft = verdict.data_flow_trace
            data_flow_block = (
                f"- Source: {dft.source or 'unknown'}\n"
                f"- Sink: {dft.sink or 'unknown'}\n"
                f"- Flow: {dft.flow or 'unknown'}\n"
                f"- Existing Protection: {dft.protection or 'none'}"
            )
        else:
            data_flow_block = "- Data Flow Trace: not provided (infer directly from the method below)"

        existing_imports = _extract_existing_imports(finding.file_path)

        callee_block = (
            "READ-ONLY Callee Reference (DO NOT include or modify this in <<<FIXED>>>):\n"
            f"```java\n{finding.callee_context}\n```\n\n"
            if finding.callee_context
            else ""
        )

        if iteration >= 2 and feedback:
            prev_block = (
                f"Your previous <<<FIXED>>> method (failed validation):\n```java\n{previous_fixed}\n```\n"
                if previous_fixed
                else ""
            )
            feedback_block = (
                f"Previous Attempt Failed (Iteration {iteration - 1}) - Fix these issues:\n"
                f"{prev_block}"
                f"Error / Validator Feedback:\n{feedback}\n\n"
            )
        else:
            feedback_block = ""

        return self.user_template.format(
            tool_name=finding.tool_name,
            rule_id=finding.rule_id,
            cwe_id=finding.cwe_id or "unknown",
            message=finding.message,
            line_start=finding.line_start,
            line_end=finding.line_end,
            reviewer_reasoning=reviewer_reasoning,
            data_flow_block=data_flow_block,
            existing_imports=existing_imports,
            numbered_code=method_code,
            callee_block=callee_block,
            feedback_block=feedback_block,
        )

    def _fail_open(
        self,
        finding: Finding,
        iteration: int,
        parse_error: Optional[str] = None,
        llm_error: Optional[str] = None,
    ) -> Module3Patch:
        return Module3Patch(
            finding_id=finding.finding_id,
            original_snippet=finding.function_context or "",
            fixed_snippet="",
            line_start=finding.context_start_line,
            line_end=finding.context_end_line,
            explanation=None,
            required_imports=[],
            parse_error=parse_error,
            llm_error=llm_error,
            iteration=iteration,
            source="fail_open",
            model=getattr(self.client, "model", None),
        )
