"""
pipeline.py
Ghép nối toàn bộ Tầng 1: chạy SAST tool -> lọc nhiễu -> trích context -> 
trả về list[Finding] hoàn chỉnh, sẵn sàng cho Tầng 2 (Reviewer Agent).
"""

import uuid
from .aggregator import SASTAggregator
from .context_extractor import JavaContextExtractor
from .base import RawFinding
from src.schemas import Finding


# Các mức severity/confidence coi là noise, loại bỏ trước khi đưa sang Reviewer
SEVERITY_BLOCKLIST = {"INFO"}
CONFIDENCE_BLOCKLIST = {"LOW"}


class ScannerPipeline:
    def __init__(self, aggregator: SASTAggregator, context_extractor: JavaContextExtractor):
        self.aggregator = aggregator
        self.context_extractor = context_extractor

    def run(self, target_path: str) -> list[Finding]:
        raw_findings = self.aggregator.run_all(target_path)
        filtered = self._filter_noise(raw_findings)

        findings: list[Finding] = []
        skipped_no_context = 0

        for raw in filtered:
            context = self._safe_extract_context(raw)

            if context is None:
                skipped_no_context += 1

            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                tool_name=raw.tool_name,
                rule_id=raw.rule_id,
                cwe_id=raw.cwe_id,
                file_path=raw.file_path,
                line_start=raw.line_start,
                line_end=raw.line_end,
                message=raw.message,
                severity=raw.severity,
                confidence=raw.confidence,
                remediation_advice=raw.remediation_advice,
                suggested_fix_snippet=raw.suggested_fix_snippet,
                references=raw.references,
                method_name=context["method_name"] if context else None,
                function_context=context["source"] if context else None,
                context_start_line=context["start_line"] if context else None,
                context_end_line=context["end_line"] if context else None,
            ))

        print(f"[INFO] Pipeline: {len(raw_findings)} raw -> {len(filtered)} sau loc "
              f"-> {len(findings)} Finding hoan chinh "
              f"({skipped_no_context} khong trich duoc context)")

        return findings

    def _filter_noise(self, findings: list[RawFinding]) -> list[RawFinding]:
        result = []
        for f in findings:
            if f.severity in SEVERITY_BLOCKLIST:
                continue
            if f.confidence in CONFIDENCE_BLOCKLIST:
                continue
            result.append(f)
        return result

    def _safe_extract_context(self, raw: RawFinding) -> dict | None:
        try:
            return self.context_extractor.extract_method(raw.file_path, raw.line_start)
        except Exception as e:
            print(f"[WARN] Khong trich duoc context cho {raw.file_path}:{raw.line_start} - {e}")
            return None