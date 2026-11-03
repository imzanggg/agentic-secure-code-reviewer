#!/usr/bin/env python3
"""Tạo trường callee_context (thân doSomething) cho các finding.
Chỉ dùng mã nguồn, không dùng nhãn. Bỏ comment. Giữ nguyên finding_id và mọi trường khác.
Ghi ra file mới, không ghi đè tier1_findings.json."""
import argparse, json, re, textwrap
from pathlib import Path

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

T = re.compile(r"(BenchmarkTest\d+)")
CALL = re.compile(r"\bdoSomething\s*\(")
DEF = re.compile(r"\b(?:String|Object|boolean|int)\s+doSomething\s*\(")
PARSER = Parser(Language(tsjava.language()))


def strip_comments(code: str) -> str:
    """Bỏ // và /* */, tôn trọng chuỗi và ký tự để không cắt nhầm "http://..."."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c in "\"'":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            out.append(code[i:j + 1])
            i = j + 1
        elif code.startswith("//", i):
            j = code.find("\n", i)
            i = n if j == -1 else j
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    lines = [l.rstrip() for l in "".join(out).split("\n")]
    return "\n".join(l for l in lines if l.strip())


def methods_named(path: Path, name: str):
    """Mọi method_declaration tên `name` trong file (kể cả trong lớp lồng), đã bỏ comment."""
    data = path.read_bytes()
    tree = PARSER.parse(data)
    lines = data.decode("utf-8", errors="replace").split("\n")
    spans, stack = [], [tree.root_node]
    while stack:
        nd = stack.pop()
        if nd.type == "method_declaration":
            nm = nd.child_by_field_name("name")
            if nm is not None and nm.text.decode("utf-8") == name:
                spans.append((nd.start_point[0], nd.end_point[0]))
        stack.extend(nd.children)
    spans.sort()
    return [strip_comments(textwrap.dedent("\n".join(lines[s:e + 1]))) for s, e in spans]


def thing_impls(test_file: Path):
    """Các cài đặt ThingInterface trong helpers/ (Thing1, Thing2...)."""
    res = []
    helpers = test_file.parent.parent / "helpers"
    if helpers.is_dir():
        for f in sorted(helpers.glob("Thing*.java")):
            if f.stem in ("ThingFactory", "ThingInterface"):
                continue
            res += [f"// {f.stem}\n{m}" for m in methods_named(f, "doSomething")]
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="data/results/tier1_findings.json")
    ap.add_argument("--split-file", default="data/splits/dev_test_split.json")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--out", default="data/results/tier1_findings_callee.json")
    a = ap.parse_args()

    names = set(json.load(open(a.split_file, encoding="utf-8"))[a.split])
    fnd = [x for x in json.load(open(a.findings, encoding="utf-8"))
           if (m := T.search(x["file_path"])) and m.group(1) in names]

    stat = {"khong_goi": 0, "da_co_dinh_nghia": 0, "trong_file": 0,
            "thing": 0, "khong_tim_thay": 0}
    miss, sizes, example = [], [], {}
    for x in fnd:
        x["callee_context"] = None
        ctx = x.get("function_context") or ""
        if not CALL.search(ctx):
            stat["khong_goi"] += 1
            continue
        if DEF.search(ctx):
            stat["da_co_dinh_nghia"] += 1
            continue
        path = Path(x["file_path"])
        defs = methods_named(path, "doSomething")
        kind = "trong_file"
        if not defs:
            defs, kind = thing_impls(path), "thing"
        if not defs:
            stat["khong_tim_thay"] += 1
            miss.append(path.name)
            continue
        stat[kind] += 1
        x["callee_context"] = "\n\n".join(defs)
        example.setdefault(kind, (path.name, x["callee_context"]))
        sizes.append((len(ctx) + len(x["callee_context"])) // 3)  # ước lượng token, thận trọng

    json.dump(fnd, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(a.split, "| finding:", len(fnd), "|", stat)
    if sizes:
        print("ước lượng token function_context + callee: max", max(sizes),
              "| trung bình", sum(sizes) // len(sizes), "(num_ctx 8192, chưa tính prompt)")
    if miss:
        print("không tìm thấy:", miss)
    for kind, (name, code) in example.items():
        print(f"\n== ví dụ {kind}: {name} ==\n{code}")


if __name__ == "__main__":
    main()