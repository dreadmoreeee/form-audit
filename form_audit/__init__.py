"""Read-only audit of the forms on a web page: labels, autocomplete, keyboards, errors, passwords, targets."""

__version__ = "1.0.0"

from .autofill import infer_field, parse_autocomplete  # noqa: E402
from .rules import Finding, PageReport, audit_page, exit_code  # noqa: E402

__all__ = ["Finding", "PageReport", "audit_page", "exit_code", "infer_field", "parse_autocomplete", "__version__"]
