"""
spotbugs_tool.py
Tích hợp SpotBugs + FindSecBugs plugin thông qua Maven profile 'findsecbugs'.
Hỗ trợ quét toàn bộ thư mục testcase hoặc quét nhanh 1 file đơn lẻ,
tự động lọc bỏ các finding từ thư mục scaffolding/helpers.
"""

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from .base import RawFinding, SASTTool


class SpotBugsTool(SASTTool):
    name = "spotbugs"

    def __init__(self, timeout: int = 1800):
        self.timeout = timeout

    def run(self, target_path: str) -> List[RawFinding]:
        target = Path(target_path).resolve()
        pom_dir = self._find_pom_dir(target)
        if not pom_dir:
            raise FileNotFoundError(
                f"Không tìm thấy pom.xml ở các thư mục cha của: {target_path}"
            )

        # Kiểm tra xem target là 1 file đơn hay toàn bộ thư mục
        single_class: Optional[str] = None
        if target.is_file() and target.suffix == ".java":
            # Chuyển BenchmarkTest00001.java -> org.owasp.benchmark.testcode.BenchmarkTest00001
            single_class = f"org.owasp.benchmark.testcode.{target.stem}"

        # 1. Chạy Maven compile + spotbugs
        self._run_maven_spotbugs(pom_dir, single_class)

        # 2. Parse XML kết quả
        xml_path = pom_dir / "target" / "spotbugsXml.xml"
        if not xml_path.exists():
            # Dự phòng tên file XML mặc định khác của plugin
            fallback = pom_dir / "target" / "spotbugs.xml"
            if fallback.exists():
                xml_path = fallback
            else:
                print(f"[WARN] Không tìm thấy file kết quả SpotBugs XML tại {xml_path}")
                return []

        return self._parse_spotbugs_xml(xml_path, pom_dir, target)

    def _find_pom_dir(self, start_path: Path) -> Optional[Path]:
        current = start_path if start_path.is_dir() else start_path.parent
        while current != current.parent:
            if (current / "pom.xml").exists():
                return current
            current = current.parent
        return None

    def _run_maven_spotbugs(self, pom_dir: Path, single_class: Optional[str] = None):
        cmd = [
            "mvn",
            "compile",
            "spotbugs:spotbugs",
            "-Pfindsecbugs",
            "-Dspotbugs.failOnError=false",
            "-Dspotbugs.xmlOutput=true",
            "-Denforcer.skip=true",
            "-DskipTests",
            "-q",
        ]

        if single_class:
            # Quét riêng 1 file để phục vụ chu trình lặp Agentic siêu tốc (~1-2s)
            cmd.append(f"-Dspotbugs.onlyAnalyze={single_class}")

        print(f"[INFO] Đang chạy SpotBugs qua Maven tại {pom_dir}...")
        res = subprocess.run(
            cmd,
            cwd=str(pom_dir),
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

        if res.returncode != 0 and not (pom_dir / "target" / "spotbugsXml.xml").exists():
            print(f"[ERROR] Maven SpotBugs thất bại:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")

    def _parse_spotbugs_xml(self, xml_path: Path, pom_dir: Path, target_path: Path) -> List[RawFinding]:
        findings: List[RawFinding] = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as e:
            print(f"[ERROR] Lỗi đọc file XML {xml_path}: {e}")
            return findings

        # Nguồn source gốc của Benchmark: src/main/java
        source_root = pom_dir / "src" / "main" / "java"
        priority_map = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}

        for bug in root.findall("BugInstance"):
            # Lấy CWE: findsecbugs thường để ở thuộc tính cweid="89"
            cwe_id_raw = bug.get("cweid")
            cwe_id = f"CWE-{cwe_id_raw}" if cwe_id_raw else None

            # Lấy thông tin dòng code từ thẻ SourceLine chính
            source_line = bug.find("SourceLine")
            if source_line is None:
                continue

            rel_source_path = source_line.get("sourcepath")
            if not rel_source_path:
                continue

            # Ánh xạ về đường dẫn file .java thật trên disk
            full_file_path = (source_root / rel_source_path).resolve()

            # Lọc bỏ các file nằm ngoài phạm vi target_path (ví dụ: các file helpers/)
            if not str(full_file_path).startswith(str(target_path)):
                continue

            try:
                line_start = int(source_line.get("start", 1))
                line_end = int(source_line.get("end", line_start))
            except ValueError:
                line_start, line_end = 1, 1

            long_msg_node = bug.find("LongMessage")
            short_msg_node = bug.find("ShortMessage")
            message = (
                long_msg_node.text
                if long_msg_node is not None and long_msg_node.text
                else (short_msg_node.text if short_msg_node is not None else bug.get("type", "Security Bug"))
            )

            priority = bug.get("priority", "2")
            severity = priority_map.get(priority, "MEDIUM")

            findings.append(
                RawFinding(
                    tool_name=self.name,
                    rule_id=bug.get("type", "UNKNOWN_RULE"),
                    cwe_id=cwe_id,
                    file_path=str(full_file_path),
                    line_start=line_start,
                    line_end=line_end,
                    message=message.strip(),
                    severity=severity,
                    confidence=severity,
                    remediation_advice=message.strip(),
                    suggested_fix_snippet=None,
                    references=[],
                )
            )

        return findings
