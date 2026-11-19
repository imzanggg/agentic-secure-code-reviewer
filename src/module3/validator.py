"""
validator.py
Validator nhẹ cho Module 3: thực hiện các bước kiểm định tuần tự sau khi áp bản vá:
1. Áp bản vá + import vào file (patch_applier)
2. Kiểm tra nhanh cú pháp & chữ ký method bằng tree-sitter (~1ms)
3. Biên dịch Maven (mvn compile)
4. Quét lại SAST trên đúng file/class đã sửa (SpotBugs single_class / Semgrep single file)
"""

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Tuple

from src.scanner.base import RawFinding
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.schemas import Finding
from src.module3.patch_applier import apply_patch_to_file, check_syntax_and_signature, extract_method_signature
from src.module3.schemas import Module3Patch, PatchApplyResult, ValidationResult

SEVERITY_BLOCKLIST = {"INFO"}
CONFIDENCE_BLOCKLIST = {"LOW"}
CWE_EQUIVALENT = {"CWE-327": {"CWE-326"}, "CWE-326": {"CWE-327"}}

COMPILE_ERR_LINE_RE = re.compile(r"^\[ERROR\]\s*(.+)$")


def _filter_noise(findings: List[RawFinding]) -> List[RawFinding]:
    return [
        f for f in findings
        if f.severity not in SEVERITY_BLOCKLIST and f.confidence not in CONFIDENCE_BLOCKLIST
    ]


def _cwe_matches(target_cwe: Optional[str], found_cwe: Optional[str]) -> bool:
    if not target_cwe or not found_cwe:
        return False
    if target_cwe == found_cwe:
        return True
    return found_cwe in CWE_EQUIVALENT.get(target_cwe, set())


def _find_pom_dir(start_path: Path) -> Optional[Path]:
    cur = start_path if start_path.is_dir() else start_path.parent
    while cur != cur.parent:
        if (cur / "pom.xml").exists():
            return cur
        cur = cur.parent
    return None


def _extract_compile_errors(stdout: str, stderr: str, max_lines: int = 12) -> str:
    combined = (stdout or "") + "\n" + (stderr or "")
    err_lines: List[str] = []
    for line in combined.splitlines():
        m = COMPILE_ERR_LINE_RE.match(line.strip())
        if m:
            msg = m.group(1).strip()
            if msg and not msg.startswith(("To see the full stack trace", "Re-run Maven", "For more information", "-> [Help")):
                err_lines.append(msg)
        elif "error:" in line.lower():
            err_lines.append(line.strip())

    if not err_lines:
        tail = [l.strip() for l in combined.splitlines() if l.strip()][-max_lines:]
        return "\n".join(tail) or "Maven compilation failed."
    return "\n".join(err_lines[:max_lines])


class PatchValidator:
    def __init__(
        self,
        semgrep_tool: Optional[SemgrepTool] = None,
        spotbugs_tool: Optional[SpotBugsTool] = None,
        check_all_tools: bool = False,
        compile_timeout: int = 180,
    ):
        self.semgrep = semgrep_tool or SemgrepTool(ruleset="p/java")
        self.spotbugs = spotbugs_tool or SpotBugsTool()
        self.check_all_tools = check_all_tools
        self.compile_timeout = compile_timeout

    def validate(
        self,
        finding: Finding,
        patch: Module3Patch,
    ) -> Tuple[Optional[PatchApplyResult], ValidationResult]:
        # 0a. Kiểm tra lỗi gọi LLM (timeout, HTTP 404, mất kết nối...)
        if patch.llm_error:
            return None, ValidationResult(
                failure_stage="llm_error",
                feedback=f"LLM call failed: {patch.llm_error}",
            )

        # 0b. Kiểm tra lỗi parse định dạng output từ LLM
        if patch.parse_error:
            return None, ValidationResult(
                failure_stage="parse",
                feedback=f"Output format error: {patch.parse_error}",
            )

        # Lưu chữ ký method gốc trước khi vá để đối chiếu
        orig_sig = extract_method_signature(finding.file_path, finding.line_start)

        # 1. Áp bản vá vào file
        apply_res = apply_patch_to_file(finding, patch)
        if not apply_res.applied:
            return apply_res, ValidationResult(
                failure_stage="apply",
                feedback=apply_res.error or "Failed to apply patch.",
            )

        check_line = apply_res.line_start or finding.line_start

        # 2. Kiểm tra nhanh cú pháp & chữ ký hàm bằng tree-sitter
        syntax_ok, sig_ok, ts_err = check_syntax_and_signature(
            file_path=finding.file_path,
            target_line=check_line,
            original_signature=orig_sig,
        )
        if not syntax_ok:
            return apply_res, ValidationResult(
                syntax_valid=False,
                signature_preserved=False,
                failure_stage="syntax",
                feedback=ts_err,
            )
        if not sig_ok:
            return apply_res, ValidationResult(
                syntax_valid=True,
                signature_preserved=False,
                failure_stage="signature",
                feedback=ts_err,
            )

        # 3. Biên dịch Maven
        compiled, compile_err = self._run_mvn_compile(finding.file_path)
        if not compiled:
            return apply_res, ValidationResult(
                syntax_valid=True,
                signature_preserved=True,
                compiled=False,
                failure_stage="compile",
                feedback=f"Maven compilation failed:\n{compile_err}",
            )

        # 4. Quét lại SAST trên đúng file đã sửa
        sast_ok, remaining_cnt, new_cwes, sast_feedback = self._rescan_sast(finding, apply_res)
        return apply_res, ValidationResult(
            syntax_valid=True,
            signature_preserved=True,
            compiled=True,
            sast_passed=sast_ok,
            failure_stage=None if sast_ok else "sast",
            feedback=sast_feedback,
            remaining_findings_count=remaining_cnt,
            new_cwe_ids=new_cwes,
        )

    def _run_mvn_compile(self, file_path: str) -> Tuple[bool, Optional[str]]:
        pom_dir = _find_pom_dir(Path(file_path).resolve())
        if not pom_dir:
            return False, f"pom.xml not found above {file_path}"

        cmd = [
            "mvn",
            "compile",
            "-Denforcer.skip=true",
            "-Dspotless.skip=true",
            "-DskipTests",
            "-B",
        ]
        try:
            res = subprocess.run(
                cmd,
                cwd=str(pom_dir),
                capture_output=True,
                text=True,
                timeout=self.compile_timeout,
            )
        except Exception as e:
            return False, f"Failed to execute mvn compile: {e}"

        if res.returncode != 0:
            return False, _extract_compile_errors(res.stdout, res.stderr)
        return True, None

    def _rescan_sast(
        self,
        finding: Finding,
        apply_res: PatchApplyResult,
    ) -> Tuple[bool, int, List[str], Optional[str]]:
        tool_tag = (finding.tool_name or "").lower()
        run_semgrep = self.check_all_tools or ("semgrep" in tool_tag) or (not tool_tag)
        run_spotbugs = self.check_all_tools or ("spotbugs" in tool_tag) or (not tool_tag)

        raw_results: List[RawFinding] = []
        if run_semgrep:
            raw_results.extend(self.semgrep.run(finding.file_path))
        if run_spotbugs:
            raw_results.extend(self.spotbugs.run(finding.file_path))

        filtered = _filter_noise(raw_results)

        added_imp_lines = len(apply_res.added_imports)
        method_start = (finding.context_start_line or 1) + added_imp_lines
        patch_len_delta = (
            (apply_res.line_end - apply_res.line_start + 1)
            if (apply_res.line_start and apply_res.line_end)
            else 0
        )
        method_end = (finding.context_end_line or 10**6) + added_imp_lines + max(patch_len_delta, 10)

        persisting: List[RawFinding] = []
        introduced: List[RawFinding] = []
        new_cwes: Set[str] = set()

        for rf in filtered:
            in_method = method_start <= rf.line_start <= method_end
            if not in_method:
                continue

            same_cwe = _cwe_matches(finding.cwe_id, rf.cwe_id) or (
                not finding.cwe_id and rf.rule_id == finding.rule_id
            )
            if same_cwe:
                persisting.append(rf)
            elif (
                apply_res.line_start is not None
                and apply_res.line_end is not None
                and apply_res.line_start <= rf.line_start <= apply_res.line_end
            ):
                introduced.append(rf)
                if rf.cwe_id:
                    new_cwes.add(rf.cwe_id)

        if not persisting and not introduced:
            return True, 0, [], None

        notes: List[str] = []
        for rf in persisting:
            notes.append(
                f"Vulnerability still detected ({rf.tool_name} / {rf.cwe_id or rf.rule_id} at line {rf.line_start}): {rf.message}"
            )
        for rf in introduced:
            notes.append(
                f"New vulnerability introduced on patched lines ({rf.tool_name} / {rf.cwe_id or rf.rule_id} at line {rf.line_start}): {rf.message}"
            )

        return False, len(persisting) + len(introduced), sorted(new_cwes), "\n".join(notes)
