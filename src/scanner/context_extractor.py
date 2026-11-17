"""context_extractor.py: trích method + callee context bằng tree-sitter-java."""

import re
import textwrap
from pathlib import Path
from typing import Optional
from tree_sitter import Language, Parser
import tree_sitter_java as tsjava

CALL_RE = re.compile(r"\bdoSomething\s*\(")
DEF_RE = re.compile(r"\b(?:String|Object|boolean|int|void)\s+doSomething\s*\(")


class JavaContextExtractor:
    def __init__(self):
        java_language = Language(tsjava.language())
        self.parser = Parser(java_language)

    def extract_method(self, file_path: str, target_line: int) -> Optional[dict]:
        """
        Trả về method chứa target_line (1-indexed), gồm source code,
        tên method, vị trí thật trong file, và callee_context (nếu có).
        """
        source_bytes = Path(file_path).read_bytes()
        tree = self.parser.parse(source_bytes)

        method_node = self._find_enclosing_method(tree.root_node, target_line)
        if method_node is None:
            return None

        method_source = source_bytes[method_node.start_byte:method_node.end_byte].decode(
            "utf-8", errors="replace"
        )
        method_name = self._get_method_name(method_node)
        callee_context = self.extract_callee_context(file_path, method_source)

        return {
            "method_name": method_name,
            "source": method_source,
            "start_line": method_node.start_point[0] + 1,
            "end_line": method_node.end_point[0] + 1,
            "callee_context": callee_context,
        }

    def extract_callee_context(self, file_path: str, method_source: str) -> Optional[str]:
        """Trích xuất thân hàm callee (vd: doSomething / Thing*.java) và bỏ comment."""
        if not method_source or not CALL_RE.search(method_source):
            return None
        if DEF_RE.search(method_source):
            return None

        path = Path(file_path)
        defs = self._methods_named(path, "doSomething")
        if not defs:
            defs = self._thing_impls(path)
        return "\n\n".join(defs) if defs else None

    def _methods_named(self, path: Path, name: str) -> list[str]:
        if not path.exists():
            return []
        data = path.read_bytes()
        tree = self.parser.parse(data)
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
        return [self._strip_comments(textwrap.dedent("\n".join(lines[s:e + 1]))) for s, e in spans]

    def _thing_impls(self, test_file: Path) -> list[str]:
        res = []
        helpers = test_file.parent.parent / "helpers"
        if helpers.is_dir():
            for f in sorted(helpers.glob("Thing*.java")):
                if f.stem in ("ThingFactory", "ThingInterface"):
                    continue
                res += [f"// {f.stem}\n{m}" for m in self._methods_named(f, "doSomething")]
        return res

    @staticmethod
    def _strip_comments(code: str) -> str:
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

    def _find_enclosing_method(self, node, target_line: int):
        if node.type == "method_declaration":
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= target_line <= end:
                for child in node.children:
                    deeper = self._find_enclosing_method(child, target_line)
                    if deeper is not None:
                        return deeper
                return node
        for child in node.children:
            result = self._find_enclosing_method(child, target_line)
            if result is not None:
                return result
        return None

    def _get_method_name(self, method_node) -> str:
        for child in method_node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
        return "unknown_method"