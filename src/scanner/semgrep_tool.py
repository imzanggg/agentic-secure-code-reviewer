"""semgrep_tool.py"""

import json
import subprocess
from .base import SASTTool, RawFinding


class SemgrepTool(SASTTool):
    name = "semgrep"

    def __init__(self, ruleset: str = "p/java", timeout: int = 600):
        self.ruleset = ruleset
        self.timeout = timeout

    def run(self, target_path: str) -> list[RawFinding]:
        cmd = ["semgrep", "--config", self.ruleset, "--json",
               "--metrics=off", target_path]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=self.timeout)
        data = json.loads(result.stdout)

        findings = []
        for r in data.get("results", []):
            extra = r["extra"]
            meta = extra.get("metadata", {})

            cwe_raw = meta.get("cwe", [])
            cwe_id = cwe_raw[0].split(":")[0].strip() if cwe_raw else None

            findings.append(RawFinding(
                tool_name=self.name,
                rule_id=r["check_id"],
                cwe_id=cwe_id,
                file_path=r["path"],
                line_start=r["start"]["line"],
                line_end=r["end"]["line"],
                message=extra["message"],
                severity=extra["severity"],
                confidence=meta.get("confidence"),
                remediation_advice=extra["message"],       # Semgrep nhúng advice ngay trong message
                suggested_fix_snippet=extra.get("fix"),      # chỉ có nếu rule hỗ trợ autofix
                references=meta.get("references", []),
            ))
        return findings