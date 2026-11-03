from src.agents.reviewer import parse_text_output

CASES = [
    ("00257", "...which is a weak cipher.\n\n### Decision\nFP | CONFIDENCE: low", "FP", "low"),
    ("00608", "...security-sensitive purpose.\n\n### Decision\nFP | CONFIDENCE: low", "FP", "low"),
    ("00609", "...a strong random number generator.\n\n### Decision\nFP | CONFIDENCE: low", "FP", "low"),
    ("01589", "6. The `printf` method does not write bar.\n\nDECISION: FP | CONFIDENCE: low", "FP", "low"),
    ("01893", "...is vulnerable to XSS.\n\n**Decision:** TP | CONFIDENCE: high", "TP", "high"),
    ("02308", "Conclusion:\nThe warning is a false alarm. The value of param is not security sensitive.", None, None),
    # ca dòng chuẩn phải vẫn đúng
    ("chuan", "Analysis here.\nDECISION: TP | CONFIDENCE: medium", "TP", "medium"),
    # lập luận có nhắc "TP" giữa chừng, chỉ dòng cuối được tính
    ("nhac_giua", "Not a TP because x.\nDECISION: FP | CONFIDENCE: high", "FP", "high"),
]

for name, text, verdict, conf in CASES:
    out = parse_text_output(text)
    got = (out.verdict, out.confidence) if out else (None, None)
    assert got == (verdict, conf), f"{name}: {got} != {(verdict, conf)}"
    if out:
        assert not out.reasoning.lower().rstrip().endswith("decision"), name
    print("ok", name)