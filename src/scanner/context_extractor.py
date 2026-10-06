"""context_extractor.py: trích method chứa dòng bị flag bằng tree-sitter-java."""

from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_java as tsjava


class JavaContextExtractor:
    def __init__(self):
        java_language = Language(tsjava.language())
        self.parser = Parser(java_language)

    def extract_method(self, file_path: str, target_line: int) -> dict | None:
        """
        Trả về method chứa target_line (1-indexed), gồm source code,
        tên method, và vị trí bắt đầu/kết thúc thật trong file.
        """
        source_bytes = Path(file_path).read_bytes()
        tree = self.parser.parse(source_bytes)

        method_node = self._find_enclosing_method(tree.root_node, target_line)
        if method_node is None:
            return None

        method_source = source_bytes[method_node.start_byte:method_node.end_byte].decode("utf-8", errors="replace")
        method_name = self._get_method_name(method_node)

        return {
            "method_name": method_name,
            "source": method_source,
            "start_line": method_node.start_point[0] + 1,  # tree-sitter 0-indexed -> đổi về 1-indexed
            "end_line": method_node.end_point[0] + 1,
        }

    def _find_enclosing_method(self, node, target_line: int):
        """Duyệt AST tìm node kiểu method_declaration bao trùm target_line."""
        if node.type == "method_declaration":
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= target_line <= end:
                # Tiếp tục tìm sâu hơn phòng trường hợp có method lồng (hiếm ở Java nhưng an toàn)
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