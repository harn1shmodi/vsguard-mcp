"""Semgrep scanner integration."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..asvs.mapper import get_asvs_mapper
from ..config import settings
from ..models import Location, ScanResult, SeverityLevel
from .base import BaseScanner

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    """Security scanner using Semgrep."""

    # Language support
    SUPPORTED_LANGUAGES = {
        "python": "py",
        "py": "py",
        "javascript": "js",
        "js": "js",
        "typescript": "ts",
        "ts": "ts",
        "java": "java",
        "go": "go",
        "ruby": "rb",
        "php": "php",
        "c": "c",
        "cpp": "cpp",
        "csharp": "cs",
        "rust": "rs",
    }

    # Map Semgrep severity to our severity levels
    SEVERITY_MAP = {
        "ERROR": SeverityLevel.HIGH,
        "WARNING": SeverityLevel.MEDIUM,
        "INFO": SeverityLevel.LOW,
    }

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        """
        Initialize Semgrep scanner.

        Args:
            rules_dir: Directory containing custom Semgrep rules
        """
        self.rules_dir = rules_dir or settings.rules_path
        self.mapper = get_asvs_mapper()

    async def scan(
        self,
        code: str,
        language: str,
        filename: Optional[str] = None,
    ) -> list[ScanResult]:
        """
        Scan code using Semgrep.

        Args:
            code: Source code to scan
            language: Programming language
            filename: Optional filename for context

        Returns:
            List of security findings
        """
        if not self.supports_language(language):
            logger.warning(f"Language not supported by Semgrep: {language}")
            return []

        # Determine file extension
        extension = self._get_file_extension(language)
        if not filename:
            filename = f"input.{extension}"

        # Create temporary file with the code
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            code_file = tmpdir_path / filename
            
            # Create parent directories if filename has path components
            code_file.parent.mkdir(parents=True, exist_ok=True)
            
            code_file.write_text(code, encoding="utf-8")

            # Run Semgrep
            results = await self._run_semgrep(code_file, tmpdir_path)

        return results

    def supports_language(self, language: str) -> bool:
        """Check if Semgrep supports this language."""
        return language.lower() in self.SUPPORTED_LANGUAGES

    async def _run_semgrep(self, code_file: Path, working_dir: Path) -> list[ScanResult]:
        """
        Run Semgrep on a file.

        Args:
            code_file: Path to code file
            working_dir: Working directory

        Returns:
            List of scan results
        """
        try:
            # Build Semgrep command
            cmd = [
                "semgrep",
                "--config=auto",  # Use Semgrep Registry rules
                "--json",
                "--no-git-ignore",
                "--timeout", str(settings.scan_timeout),
            ]

            # Add custom rules if available
            if self.rules_dir.exists():
                cmd.extend(["--config", str(self.rules_dir)])
                logger.debug(f"Using custom rules from: {self.rules_dir}")

            cmd.append(str(code_file))

            # Run Semgrep
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout,
            )

            # Parse JSON output
            if result.stdout:
                output = json.loads(result.stdout)
                return self._parse_semgrep_output(output, code_file.name)
            else:
                logger.warning("Semgrep returned no output")
                return []

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {settings.scan_timeout}s")
            return []
        except FileNotFoundError:
            logger.error("Semgrep not found - please install: pip install semgrep")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}", exc_info=True)
            return []

    def _parse_semgrep_output(self, output: dict, filename: str) -> list[ScanResult]:
        """
        Parse Semgrep JSON output into ScanResult objects.

        Args:
            output: Semgrep JSON output
            filename: Filename that was scanned

        Returns:
            List of scan results
        """
        results = []

        for finding in output.get("results", []):
            try:
                # Extract rule metadata
                rule_id = finding.get("check_id", "")
                message = finding.get("extra", {}).get("message", finding.get("message", ""))
                severity = finding.get("extra", {}).get("severity", "WARNING")

                # Extract location info
                start = finding.get("start", {})
                end = finding.get("end", {})
                line = start.get("line")
                column = start.get("col")
                end_line = end.get("line")

                # Extract code snippet
                code_snippet = finding.get("extra", {}).get("lines", "")

                # Extract metadata
                metadata = finding.get("extra", {}).get("metadata", {})
                vulnerability_type = metadata.get("vulnerability", rule_id.split(".")[-1])
                cwe = metadata.get("cwe")
                asvs_id = metadata.get("asvs_id")

                # Map to ASVS requirements
                asvs_requirements = []
                if asvs_id:
                    asvs_requirements.append(asvs_id)
                else:
                    # Try to map based on vulnerability type and CWE
                    asvs_requirements = self.mapper.map_finding_to_asvs(
                        vulnerability_type=vulnerability_type,
                        cwe=cwe,
                    )

                # Build remediation message
                remediation = metadata.get("remediation", "Review and fix this security issue.")

                # Create scan result
                result = ScanResult(
                    severity=self.SEVERITY_MAP.get(severity.upper(), SeverityLevel.MEDIUM),
                    vulnerability_type=vulnerability_type,
                    asvs_requirements=asvs_requirements,
                    location=Location(
                        line=line,
                        column=column,
                        end_line=end_line,
                        filename=filename,
                        code_snippet=code_snippet,
                    ),
                    message=message,
                    remediation=remediation,
                    scanner="semgrep",
                    metadata={
                        "rule_id": rule_id,
                        "cwe": cwe,
                    },
                )

                results.append(result)

            except Exception as e:
                logger.error(f"Error parsing Semgrep finding: {e}", exc_info=True)
                logger.debug(f"Finding data: {finding}")
                continue

        return results

    def _get_file_extension(self, language: str) -> str:
        """Get file extension for a language."""
        return self.SUPPORTED_LANGUAGES.get(language.lower(), "txt")

