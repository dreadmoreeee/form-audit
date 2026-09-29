"""Command line: python -m form_audit URL [URL ...]"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit

from . import __version__
from .report import to_json, to_markdown
from .rules import audit_page, exit_code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="form-audit",
        description="Audit the forms on web pages without submitting anything (read-only, headless Chromium).",
    )
    p.add_argument("urls", nargs="*", metavar="URL", help="http(s) page(s) to audit")
    p.add_argument("--format", choices=("md", "json"), default="md", help="output format (default: md)")
    p.add_argument("--fail-on", choices=("high", "medium", "low", "never"), default="high",
                   help="exit 1 when an issue at or above this level is found (default: high)")
    p.add_argument("--input", metavar="FILE", help="audit previously extracted page data (JSON) instead of loading URLs")
    p.add_argument("--raw", action="store_true", help="print the extracted page data as JSON, without rules")
    p.add_argument("--timeout", type=float, default=30.0, help="page load timeout in seconds (default: 30)")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between page loads (default: 1, minimum 1)")
    p.add_argument("--mobile", action="store_true", help="use a 390x844 touch viewport")
    p.add_argument("--user-agent", default=None, help="override the User-Agent header")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--version", action="version", version=f"form-audit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.input:
        if args.urls:
            parser.error("give URLs or --input, not both")
        try:
            with open(args.input, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"form-audit: cannot read {args.input}: {exc}", file=sys.stderr)
            return 2
        pages = doc if isinstance(doc, list) else doc.get("pages", [doc])
    else:
        if not args.urls:
            parser.error("give at least one URL (or --input FILE)")
        for url in args.urls:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                parser.error(f"not an http(s) URL: {url}")
        from .extract import USER_AGENT, extract_pages

        try:
            pages = extract_pages(
                args.urls,
                timeout=args.timeout,
                delay=max(args.delay, 1.0),
                user_agent=args.user_agent or USER_AGENT,
                mobile=args.mobile,
                log=lambda m: print(m, file=sys.stderr),
            )
        except Exception as exc:  # browser could not start
            print(f"form-audit: {exc.__class__.__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=sys.stderr)
            return 2

    if args.raw:
        text = json.dumps(pages, indent=2) + "\n"
        code = 2 if any(p.get("error") for p in pages) else 0
    else:
        reports = [audit_page(p) for p in pages]
        text = to_json(reports) if args.format == "json" else to_markdown(reports)
        code = exit_code(reports, args.fail_on)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return code
