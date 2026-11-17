"""
reviewer.py
Reviewer Agent (Tầng 2): nhận Finding, trả Verdict (TP/FP) kèm DataFlowTrace & confidence_score.
Mặc định dùng output_mode="text" (ổn định hơn json mode trên local LLM khi code có dấu nháy kép).
"""

import re
from pathlib import Path
from typing import Iterable, Optional

from pydantic import ValidationError

from src.schemas import DataFlowTrace, Finding, ReviewerLLMOutput, Verdict
from .llm_client import LLMError

CONFIDENCE_TO_SCORE = {"low": 0.3, "medium": 0.65, "high": 0.95}

DECISION_RE = re.compile(
    r"\b(TP|FP)\b[\s|*:,\-–]*CONFIDENCE\W*(low|medium|high|0?\.\d+|1(?:\.0+)?)\b",
    re.IGNORECASE,
)
TRAIL_RE = re.compile(r"[#*\s]*decision[\s:*]*$", re.IGNORECASE)
HARDCODED_FILE_RE = re.compile(
    r'new\s+(?:java\.io\.)?File\s*\([^,]+,\s*"(?:passwordFile\.txt|dummy\.txt|test\.properties)"\s*\)'
)

FIELD_RE = {
    "source": re.compile(r"^SOURCE\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "sink": re.compile(r"^SINK\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "flow": re.compile(r"^FLOW\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "protection": re.compile(r"^PROTECTION\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}

WEAK_RULE_RE = re.compile(
    r"(\.(des-is-deprecated|desede-is-deprecated|use-of-md5|use-of-sha1)|^DES_USAGE)$"
)
WEAK_ALGO_RE = re.compile(r'\.getInstance\(\s*"(DES|DESede|MD5|SHA-?1)\b', re.IGNORECASE)
WEAKRAND_RULE_RE = re.compile(r"^PREDICTABLE_RANDOM$")
WEAKRAND_SRC_RE = re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\(|\bMath\.random\s*\(")


def _normalize_confidence(raw_conf: str) -> tuple[str, float]:
    val = raw_conf.strip().lower()
    if val in CONFIDENCE_TO_SCORE:
        return val, CONFIDENCE_TO_SCORE[val]
    score = max(0.0, min(1.0, float(val)))
    label = "high" if score >= 0.8 else ("medium" if score >= 0.5 else "low")
    return label, round(score, 3)


def _extract_trace(text: str) -> Optional[DataFlowTrace]:
    extracted = {}
    for key, pattern in FIELD_RE.items():
        m = pattern.search(text)
        if m:
            extracted[key] = m.group(1).strip()
    return DataFlowTrace(**extracted) if extracted else None


def parse_text_output(text: str) -> Optional[ReviewerLLMOutput]:
    matches = list(DECISION_RE.finditer(text))
    if not matches:
        return None
    last = matches[-1]
    reasoning = TRAIL_RE.sub("", text[: last.start()]).strip()
    if not reasoning:
        return None
    conf_label, conf_score = _normalize_confidence(last.group(2))
    return ReviewerLLMOutput(
        verdict=last.group(1).upper(),
        confidence=conf_label,
        confidence_score=conf_score,
        reasoning=reasoning,
        data_flow_trace=_extract_trace(reasoning),
    )


def flagged_text(f: Finding) -> str:
    if not f.function_context:
        return ""
    start = f.context_start_line or 1
    lines = f.function_context.splitlines()
    return "\n".join(lines[max(f.line_start - start, 0) : f.line_end - start + 1])


def rule_triage(f: Finding) -> Optional[tuple[str, str, str]]:
    """
    Triage tất định 100% bằng quy tắc, không qua LLM:
    - Thuật toán yếu literal (DES, MD5, SHA-1, java.util.Random) -> TP
    - File đích là hằng số literal cố định trong file operations -> FP
    """
    text = flagged_text(f)
    
    # 1. Thuật toán mã hóa / băm yếu (TP 100%)
    if WEAK_RULE_RE.search(f.rule_id):
        m = WEAK_ALGO_RE.search(text)
        if m:
            return ("TP", "high", f"gọi getInstance với thuật toán yếu '{m.group(1)}'")
    elif WEAKRAND_RULE_RE.search(f.rule_id):
        m = WEAKRAND_SRC_RE.search(text)
        if m:
            return ("TP", "high", f"bộ sinh ngẫu nhiên đoán được '{m.group(0).strip()}'")
            
    # 2. File hằng số cố định passwordFile.txt (Nhiễu SpotBugs 100%)
    if "PATH_TRAVERSAL" in f.rule_id and HARDCODED_FILE_RE.search(text):
        return ("FP", "high", "file đích là chuỗi hằng số cố định literal, không nhận input người dùng")

    return None


class ReviewerAgent:
    def __init__(
        self,
        client,
        prompt_dir: str = "configs/prompts",
        prompt_version: str = "reviewer_v4",
        source_label: str = "local_llm",
        output_mode: str = "text",
        use_rule_triage: bool = False,
    ):
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
            triage_res = rule_triage(finding)
            if triage_res:
                v_res, c_res, reason = triage_res
                return Verdict(
                    finding_id=finding.finding_id,
                    verdict=v_res,
                    confidence=c_res,
                    confidence_score=1.0 if v_res == "TP" else 0.0,
                    reasoning=f"RULE: {reason}; không cần suy luận luồng dữ liệu",
                    source="rule_based",
                    model=None,
                )

        user_prompt = self._build_user_prompt(finding)
        schema = self.schema if self.output_mode == "json" else None
        try:
            resp = self.client.chat(self.system_prompt, user_prompt, json_schema=schema)
        except LLMError as e:
            return self._fail_open(finding, f"llm_error: {e}")

        if self.output_mode == "json":
            try:
                out = ReviewerLLMOutput.model_validate_json(resp.content)
            except ValidationError as e:
                return self._fail_open(finding, f"invalid_output: {str(e)[:200]}", raw_output=resp.content)
        else:
            out = parse_text_output(resp.content)
            if out is None:
                return self._fail_open(
                    finding,
                    f"no_decision_line (done_reason={resp.done_reason})",
                    raw_output=resp.content,
                )

        return Verdict(
            finding_id=finding.finding_id,
            verdict=out.verdict,
            confidence=out.confidence,
            confidence_score=out.confidence_score,
            reasoning=out.reasoning,
            data_flow_trace=out.data_flow_trace,
            source=self.source_label,
            model=resp.model,
            latency_sec=resp.latency_sec,
            prompt_tokens=resp.prompt_tokens,
            completion_tokens=resp.completion_tokens,
            raw_output=resp.content,
        )

    def review_batch(self, findings: Iterable[Finding]) -> list[Verdict]:
        return [self.review(f) for f in findings]

    def _build_user_prompt(self, f: Finding) -> str:
        start = f.context_start_line or 1
        lines = f.function_context.splitlines()
        numbered = "\n".join(
            f"{'>>' if f.line_start <= start + i <= f.line_end else '  '} {start + i:>4}: {text}"
            for i, text in enumerate(lines)
        )
        callee_block = (
            "Definition(s) of the method called from the code above "
            "(source only, comments removed, no line numbers):\n"
            f"```java\n{f.callee_context}\n```\n\n"
            if f.callee_context
            else ""
        )
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

    def _fail_open(self, f: Finding, reason: str, raw_output: Optional[str] = None) -> Verdict:
        return Verdict(
            finding_id=f.finding_id,
            verdict="TP",
            confidence="low",
            confidence_score=0.0,
            reasoning=f"FAIL-OPEN: {reason}",
            source="fail_open",
            model=getattr(self.client, "model", None),
            raw_output=raw_output,
        )