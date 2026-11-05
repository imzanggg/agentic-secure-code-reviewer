"""
reviewer.py
Reviewer Agent (Tầng 2): nhận Finding, trả Verdict (TP/FP).
Hai giao thức đầu ra:
  json: ép JSON theo schema (cũ, bị lỗi cụt lập luận khi code có dấu nháy kép)
  text: lập luận văn bản tự do + dòng cuối 'DECISION: TP|FP | CONFIDENCE: ...'
Fail-open: mọi lỗi kỹ thuật cho verdict TP kèm source="fail_open".
"""

import re
from pathlib import Path

from pydantic import ValidationError

from src.schemas import Finding, ReviewerLLMOutput, Verdict
from .llm_client import LLMError

DECISION_RE = re.compile(
    r"\b(TP|FP)\b[\s|*:,\-–]*CONFIDENCE\W*(low|medium|high)\b", re.IGNORECASE)
# Dọn tiêu đề thừa còn dính cuối lập luận: "### Decision", "**Decision:**", "DECISION:"
TRAIL_RE = re.compile(r"[#*\s]*decision[\s:*]*$", re.IGNORECASE)


def parse_text_output(text: str):
    """Trả ReviewerLLMOutput, hoặc None nếu không có dòng quyết định hợp lệ."""
    matches = list(DECISION_RE.finditer(text))
    if not matches:
        return None
    last = matches[-1]
    reasoning = TRAIL_RE.sub("", text[:last.start()]).strip()
    if not reasoning:
        return None
    return ReviewerLLMOutput(reasoning=reasoning,
                             verdict=last.group(1).upper(),
                             confidence=last.group(2).lower())
            
WEAK_RULE_RE = re.compile(
    r"(\.(des-is-deprecated|desede-is-deprecated|use-of-md5|use-of-sha1)|^DES_USAGE)$")
WEAK_ALGO_RE = re.compile(
    r'\.getInstance\(\s*"(DES|DESede|MD5|SHA-?1)\b', re.IGNORECASE)

def flagged_text(f: Finding) -> str:
    """Nguyên văn các dòng bị cảnh báo, lấy từ function_context."""
    if not f.function_context:
        return ""
    start = f.context_start_line or 1
    lines = f.function_context.splitlines()
    return "\n".join(lines[max(f.line_start - start, 0): f.line_end - start + 1])


def rule_triage(f: Finding):
    """Trả tên thuật toán yếu nếu finding thuộc nhóm luật trên và dòng lỗi có literal
    thuật toán yếu; ngược lại None (để LLM xử lý)."""
    if not WEAK_RULE_RE.search(f.rule_id):
        return None
    m = WEAK_ALGO_RE.search(flagged_text(f))
    return m.group(1) if m else None


class ReviewerAgent:
    def __init__(self, client, prompt_dir: str = "configs/prompts",
                 prompt_version: str = "reviewer_v1", source_label: str = "local_llm",
                 output_mode: str = "json", use_rule_triage: bool = False):
        if output_mode not in ("json", "text"):
            raise ValueError("output_mode phải là 'json' hoặc 'text'")
        self.client = client
        self.prompt_version = prompt_version
        self.source_label = source_label
        self.output_mode = output_mode
        self.use_rule_triage = use_rule_triage
        base = Path(prompt_dir)
        self.system_prompt = (base / f"{prompt_version}_system.txt").read_text(encoding="utf-8")
        self.user_template = (base / f"{prompt_version}_user.txt").read_text(encoding="utf-8")
        self.schema = ReviewerLLMOutput.model_json_schema()

    def review(self, finding: Finding) -> Verdict:
        if not finding.function_context:
            return self._fail_open(finding, "no_context")
        if self.use_rule_triage:
            algo = rule_triage(finding)
            if algo:
                return Verdict(
                    finding_id=finding.finding_id, verdict="TP", confidence="high",
                    reasoning=f"RULE: dòng bị cảnh báo gọi getInstance với thuật toán yếu "
                              f"'{algo}' (literal); không cần suy luận luồng dữ liệu",
                    source="rule_based", model=None)

        user_prompt = self._build_user_prompt(finding)
        schema = self.schema if self.output_mode == "json" else None
        try:
            resp = self.client.chat(self.system_prompt, user_prompt, json_schema=schema)
        except LLMError as e:
            return self._fail_open(finding, f"llm_error: {e}")   # không có output thô

        if self.output_mode == "json":
            try:
                out = ReviewerLLMOutput.model_validate_json(resp.content)
            except ValidationError as e:
                return self._fail_open(
                    finding, f"invalid_output: {str(e)[:200]}", raw_output=resp.content)
        else:
            out = parse_text_output(resp.content)
            if out is None:
                return self._fail_open(
                    finding, f"no_decision_line (done_reason={resp.done_reason})",
                    raw_output=resp.content)

        return Verdict(
            finding_id=finding.finding_id,
            verdict=out.verdict,
            confidence=out.confidence,
            reasoning=out.reasoning,
            source=self.source_label,
            model=resp.model,
            latency_sec=resp.latency_sec,
            prompt_tokens=resp.prompt_tokens,
            completion_tokens=resp.completion_tokens,
            raw_output=resp.content,
        )

    def _build_user_prompt(self, f: Finding) -> str:
        start = f.context_start_line or 1
        lines = f.function_context.splitlines()
        numbered = "\n".join(
            f"{'>>' if f.line_start <= start + i <= f.line_end else '  '} {start + i:>4}: {text}"
            for i, text in enumerate(lines)
        )
        callee = getattr(f, "callee_context", None)
        callee_block = (
            "Definition(s) of the method called from the code above "
            "(source only, comments removed, no line numbers):\n"
            f"```java\n{callee}\n```\n\n" if callee else "")
        return self.user_template.format(
            tool_name=f.tool_name,
            rule_id=f.rule_id,
            cwe_id=f.cwe_id or "unknown",
            message=f.message,
            line_start=f.line_start,
            line_end=f.line_end,
            numbered_code=numbered,
            callee_block=callee_block,
        )

    def _fail_open(self, f: Finding, reason: str, raw_output: str | None = None) -> Verdict:
        return Verdict(
            finding_id=f.finding_id,
            verdict="TP",
            confidence="low",
            reasoning=f"FAIL-OPEN: {reason}",
            source="fail_open",
            model=getattr(self.client, "model", None),
            raw_output=raw_output,
        )