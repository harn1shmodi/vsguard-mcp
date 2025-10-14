"""Abstract base scanner interface."""

from abc import ABC, abstractmethod
from typing import Optional

from ..models import ScanResult


class BaseScanner(ABC):
    """Abstract base class for security scanners."""

    @abstractmethod
    async def scan(
        self,
        code: str,
        language: str,
        filename: Optional[str] = None,
    ) -> list[ScanResult]:
        """
        Scan code for security vulnerabilities.

        Args:
            code: Source code to scan
            language: Programming language
            filename: Optional filename for context

        Returns:
            List of security findings
        """
        pass

    @abstractmethod
    def supports_language(self, language: str) -> bool:
        """
        Check if this scanner supports a given language.

        Args:
            language: Programming language

        Returns:
            True if language is supported
        """
        pass

    def get_name(self) -> str:
        """Get scanner name."""
        return self.__class__.__name__

