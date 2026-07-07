"""Parse CLI arguments and wire the whole tool together.

This is the orchestration layer that connects loading, analysis, and
reporting. A learner should notice that it stays thin and delegates the real
work to the other modules.
"""

from __future__ import annotations

import argparse
from importlib import import_module
from pathlib import Path
import sys

from .analyzer import analyze_signin_events
from .loader import load_signin_events
from .report import build_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-log-analyzer")
    parser.add_argument("input_path", help="Path to a JSON file or directory")
    parser.add_argument("--html-out", dest="html_out", help="Write an HTML report to this path")
    args = parser.parse_args(argv)

    try:
        events = load_signin_events(args.input_path)
        result = analyze_signin_events(events)
        if args.html_out:
            html_report_module = import_module("security_log_analyzer.html_report")
            html_output = html_report_module.build_html_report(result)
            html_path = Path(args.html_out)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(html_output, encoding="utf-8")
        print(build_report(result))
        return 0
    except (
        FileNotFoundError,
        IsADirectoryError,
        PermissionError,
        ValueError,
        OSError,
        ImportError,
        AttributeError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
