"""Static security checks for Hermes Agent plugins."""

from .models import Finding, ScanResult, Severity
from .scanner import scan

__all__ = ["Finding", "ScanResult", "Severity", "scan"]
__version__ = "0.1.4"
