"""
semgrep_tool.py
Tích hợp Semgrep SAST Tool quét mã nguồn trực tiếp (Source-level SAST).
Hỗ trợ cờ --no-git-ignore để quét trong các thư mục workspace bị gitignore.
"""

import json
import subprocess
from pathlib import Path
from typing import List

from .base import SASTTool, RawFinding


class SemgrepTool(SASTTool):
    name = "semgrep"

    def __init__(self, ruleset: str = "p/java", timeout: int = 600):
        self.ruleset = ruleset
        self.timeout = timeout

    def run(self, target_path: str) -> List[RawFinding]:
        cmd = [
            "semgrep",
            "--config", self.ruleset,
            "--json",
            "--metrics=off",
            "--no-git-ignore",  # Bỏ qua gitignore để quét được trong data/workspace/
            target_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except Exception as e:
            print(f"[ERROR] Lỗi khi chạy Semgrep: {e}")
            return []

        if not result.stdout.strip():
            if result.stderr:
                print(f"[WARN] Semgrep không có output. Stderr: {result.stderr}")
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Lỗi parse JSON từ Semgrep output: {e}")
            return []

        findings = []
        for r in data.get("results", []):
            extra = r["extra"]
            meta = extra.get("metadata", {})

            cwe_raw = meta.get("cwe", [])
            cwe_id = cwe_raw[0].split(":")[0].strip() if cwe_raw else None

            findings.append(
                RawFinding(
                    tool_name=self.name,
                    rule_id=r["check_id"],
                    cwe_id=cwe_id,
                    file_path=r["path"],
                    line_start=r["start"]["line"],
                    line_end=r["end"]["line"],
                    message=extra["message"],
                    severity=extra["severity"],
                    confidence=meta.get("confidence"),
                    remediation_advice=extra["message"],     # Semgrep nhúng advice ngay trong message
                    suggested_fix_snippet=extra.get("fix"),    # Chỉ có nếu rule hỗ trợ autofix
                    references=meta.get("references", []),
                )
            )

        return findings
