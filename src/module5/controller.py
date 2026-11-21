"""
controller.py
Logic điều phối thuần túy cho Tầng 5 (Loop Controller).
Nhận kết quả từ Tầng 4 (Validator) + Tầng 2 (Re-reviewer) để quyết định:
- Dừng thành công (`resolved`) khi SAST sạch hoặc mọi cảnh báo còn lại đều là FP.
- Kích hoạt Stall Detection / Regression Guard / Max Iterations.
- Đóng gói feedback sạch (đã loại bỏ hoàn toàn FP) cho Tầng 3 ở vòng tiếp theo.
"""

import textwrap
from typing import List, Optional, Tuple
from pydantic import BaseModel

from src.module3.schemas import Module3Patch
from src.module4.schemas import PatchApplyResult, ValidationResult
from src.module5.schemas import FixIterationResult, ReReviewRecord
from src.schemas import LoopStatus


class ControllerDecision(BaseModel):
    iteration_result: FixIterationResult
    should_continue: bool
    final_status: Optional[LoopStatus] = None
    resolved_via_sast_fp_filter: bool = False
    final_failure_stage: Optional[str] = None
    next_feedback: Optional[str] = None


def _normalize_code(code: Optional[str]) -> str:
    if not code:
        return ""
    return textwrap.dedent(code).strip()


def _build_clean_tp_feedback(tp_records: List[ReReviewRecord]) -> str:
    """
    Chỉ đóng gói các finding đã được Module 2 xác nhận là TP (loại bỏ hoàn toàn FP).
    Nếu Reviewer rơi vào `fail_open`, không đưa chuỗi lỗi hạ tầng vào prompt của Fixer.
    """
    lines: List[str] = []
    for rec in tp_records:
        f = rec.finding
        v = rec.verdict
        tag = (
            "Original vulnerability still exists"
            if rec.kind == "persisting"
            else "New vulnerability introduced on patched code"
        )
        header = f"- {tag} ({f.tool_name} / {f.cwe_id or f.rule_id} at line {f.line_start}): {f.message}"
        lines.append(header)

        if v.source != "fail_open":
            if v.data_flow_trace:
                dft = v.data_flow_trace
                lines.append(
                    f"  Reviewer Trace -> Source: {dft.source or 'unknown'} | "
                    f"Sink: {dft.sink or 'unknown'} | Protection: {dft.protection or 'none'}"
                )
            elif v.reasoning:
                compact_reason = " ".join(v.reasoning.split())
                lines.append(f"  Reviewer Analysis: {compact_reason[:350]}")

    return "\n".join(lines)


def _partition_re_reviews(
    validation: ValidationResult,
    re_reviews: List[ReReviewRecord],
) -> Tuple[List[ReReviewRecord], int]:
    """Tách các cảnh báo thực sự TP sau khi qua Module 2 và đếm số FP đã lọc."""
    by_finding_id = {rec.finding.finding_id: rec for rec in re_reviews}

    confirmed_tps: List[ReReviewRecord] = []
    fp_filtered_count = 0

    ordered_inputs = [
        ("persisting", f) for f in validation.persisting_findings
    ] + [
        ("introduced", f) for f in validation.introduced_findings
    ]

    for kind, f in ordered_inputs:
        rec = by_finding_id.get(f.finding_id)
        if rec is None:
            continue
        if rec.verdict.verdict == "FP":
            fp_filtered_count += 1
        else:
            confirmed_tps.append(rec)

    return confirmed_tps, fp_filtered_count


def _detect_regression_drift(
    validation: ValidationResult,
    previous_iterations: List[FixIterationResult],
) -> bool:
    """Kiểm tra Regression Guard: tỷ lệ pass test vòng này thấp hơn vòng trước."""
    if validation.regression_pass_rate is None:
        return False
    prev_rates = [
        it.validation.regression_pass_rate
        for it in previous_iterations
        if it.validation.regression_pass_rate is not None
    ]
    if not prev_rates:
        return False
    return validation.regression_pass_rate < prev_rates[-1]


def _detect_stall(
    patch: Module3Patch,
    validation: ValidationResult,
    confirmed_tps: List[ReReviewRecord],
    previous_iterations: List[FixIterationResult],
) -> Optional[LoopStatus]:
    """
    Phát hiện bế tắc để dừng sớm:
    1. Code chuẩn hóa của vòng hiện tại trùng hệt một vòng trước đó (không sinh được hướng sửa mới).
    2. Sau >= 2 vòng trước đó đều compile thành công nhưng vẫn dính đúng cùng rule/CWE
       với số lỗi TP không giảm.
    """
    if not previous_iterations:
        return None

    curr_norm = _normalize_code(patch.fixed_snippet)
    if curr_norm:
        prev_norms = {
            _normalize_code(it.patch.fixed_snippet)
            for it in previous_iterations
            if it.patch.fixed_snippet
        }
        if curr_norm in prev_norms:
            if validation.compiled and confirmed_tps and all(r.kind == "persisting" for r in confirmed_tps):
                return "unresolved - suspected SAST FP"
            return "unresolved - max iterations exceeded"

    if validation.compiled and confirmed_tps:
        prev_compiled_sast = [
            it
            for it in previous_iterations
            if it.validation.compiled and it.confirmed_tp_count > 0
        ]
        if len(prev_compiled_sast) >= 2:
            curr_sigs = {
                (r.finding.cwe_id or r.finding.rule_id)
                for r in confirmed_tps
            }
            last_prev = prev_compiled_sast[-1]
            last_sigs = {
                (r.finding.cwe_id or r.finding.rule_id)
                for r in last_prev.re_reviews
                if r.verdict.verdict == "TP"
            }
            if (
                curr_sigs
                and curr_sigs == last_sigs
                and len(confirmed_tps) >= last_prev.confirmed_tp_count
                and all(r.kind == "persisting" for r in confirmed_tps)
            ):
                return "unresolved - suspected SAST FP"

    return None


def evaluate_iteration(
    iteration: int,
    max_iterations: int,
    patch: Module3Patch,
    apply_result: Optional[PatchApplyResult],
    validation: ValidationResult,
    re_reviews: List[ReReviewRecord],
    previous_iterations: List[FixIterationResult],
) -> ControllerDecision:
    """Hàm quyết định của `controller_node` ở cuối mỗi vòng lặp."""
    # 1. Trường hợp fail trước khi chạy SAST re-scan (llm_error, parse, apply, syntax, signature, compile)
    if not validation.compiled:
        stage = validation.failure_stage or "compile"
        feedback = None if stage == "llm_error" else validation.feedback
        it_res = FixIterationResult(
            iteration=iteration,
            patch=patch,
            apply_result=apply_result,
            validation=validation,
            re_reviews=[],
            sast_fp_filtered_count=0,
            confirmed_tp_count=0,
            sast_passed=False,
            passed=False,
            effective_failure_stage=stage,  # type: ignore[arg-type]
            clean_feedback=feedback,
        )

        if stage != "llm_error":
            stall_status = _detect_stall(patch, validation, [], previous_iterations)
            if stall_status is not None:
                it_res.effective_failure_stage = "stalled"
                return ControllerDecision(
                    iteration_result=it_res,
                    should_continue=False,
                    final_status=stall_status,
                    final_failure_stage=stage,
                )

        if iteration >= max_iterations:
            return ControllerDecision(
                iteration_result=it_res,
                should_continue=False,
                final_status="unresolved - max iterations exceeded",
                final_failure_stage=stage,
            )

        return ControllerDecision(
            iteration_result=it_res,
            should_continue=True,
            final_failure_stage=stage,
            next_feedback=feedback,
        )

    # 2. Đã compile OK: kiểm tra SAST thô vs kết quả đã lọc FP bởi Module 2
    if validation.sast_raw_clean:
        confirmed_tps: List[ReReviewRecord] = []
        fp_filtered_count = 0
        resolved_via_fp = False
    else:
        confirmed_tps, fp_filtered_count = _partition_re_reviews(validation, re_reviews)
        resolved_via_fp = (len(confirmed_tps) == 0)

    # Kiểm tra Regression Guard (nếu Tầng 4 có trả regression_pass_rate)
    if _detect_regression_drift(validation, previous_iterations):
        it_res = FixIterationResult(
            iteration=iteration,
            patch=patch,
            apply_result=apply_result,
            validation=validation,
            re_reviews=re_reviews,
            sast_fp_filtered_count=fp_filtered_count,
            confirmed_tp_count=len(confirmed_tps),
            sast_passed=(len(confirmed_tps) == 0),
            passed=False,
            effective_failure_stage="drift",
            clean_feedback=None,
        )
        return ControllerDecision(
            iteration_result=it_res,
            should_continue=False,
            final_status="unresolved - drift detection",
            final_failure_stage="drift",
        )

    # Kiểm tra Exploit PoC hook (nếu sau này Tầng 4 có trả exploit_blocked=False)
    exploit_ok = validation.exploit_blocked is not False
    sast_passed = len(confirmed_tps) == 0

    if sast_passed and exploit_ok:
        it_res = FixIterationResult(
            iteration=iteration,
            patch=patch,
            apply_result=apply_result,
            validation=validation,
            re_reviews=re_reviews,
            sast_fp_filtered_count=fp_filtered_count,
            confirmed_tp_count=0,
            sast_passed=True,
            passed=True,
            effective_failure_stage=None,
            clean_feedback=None,
        )
        return ControllerDecision(
            iteration_result=it_res,
            should_continue=False,
            final_status="resolved",
            resolved_via_sast_fp_filter=resolved_via_fp,
            final_failure_stage=None,
        )

    # 3. Còn lỗ hổng TP thực sự (hoặc exploit chưa chặn được) -> đóng gói feedback sạch
    feedback_parts: List[str] = []
    if confirmed_tps:
        feedback_parts.append(_build_clean_tp_feedback(confirmed_tps))
    if not exploit_ok:
        feedback_parts.append("- Exploit/PoC check failed: the malicious payload was not blocked.")
    clean_feedback = "\n".join(feedback_parts) if feedback_parts else validation.feedback

    it_res = FixIterationResult(
        iteration=iteration,
        patch=patch,
        apply_result=apply_result,
        validation=validation,
        re_reviews=re_reviews,
        sast_fp_filtered_count=fp_filtered_count,
        confirmed_tp_count=len(confirmed_tps),
        sast_passed=False,
        passed=False,
        effective_failure_stage="sast_tp",
        clean_feedback=clean_feedback,
    )

    stall_status = _detect_stall(patch, validation, confirmed_tps, previous_iterations)
    if stall_status is not None:
        return ControllerDecision(
            iteration_result=it_res,
            should_continue=False,
            final_status=stall_status,
            final_failure_stage="sast_tp",
        )

    if iteration >= max_iterations:
        return ControllerDecision(
            iteration_result=it_res,
            should_continue=False,
            final_status="unresolved - max iterations exceeded",
            final_failure_stage="sast_tp",
        )

    return ControllerDecision(
        iteration_result=it_res,
        should_continue=True,
        final_failure_stage="sast_tp",
        next_feedback=clean_feedback,
    )
