#!/usr/bin/env python3
"""
Lightweight Flask server to host generated HTML reports.
"""

from __future__ import annotations

import os
import sys
import logging
from pathlib import Path
from typing import List

from flask import Flask, send_from_directory, abort, redirect


def _list_reports(report_dir: Path) -> List[str]:
    """List HTML reports, excluding style.css."""
    return sorted([p.name for p in report_dir.glob("*.html") if p.is_file()])


def create_app(report_dir: str) -> Flask:
    report_path = Path(report_dir).resolve()
    app = Flask(__name__, static_folder=str(report_path), static_url_path="/reports")

    @app.route("/")
    def index():
        # Redirect to index.html if it exists
        index_file = report_path / "index.html"
        if index_file.exists():
            return redirect("/reports/index.html")
        # Otherwise show simple listing
        reports = _list_reports(report_path)
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Report Server</title>
  <link rel="stylesheet" href="/reports/style.css">
</head>
<body>
  <div class="container">
    <header>
      <h1><span class="logo">📑</span> Hosted Reports</h1>
    </header>
    {''.join(f'<div class="card"><a href="/reports/{name}">{name}</a></div>' for name in reports) or '<p>No reports found.</p>'}
  </div>
</body>
</html>"""
        return html

    @app.route("/reports/<path:filename>")
    def serve_report(filename: str):
        target = report_path / filename
        if not target.exists() or not target.is_file():
            abort(404)
        return send_from_directory(str(report_path), filename)

    return app


def serve_reports(report_dir: str = "reports", host: str = "0.0.0.0", port: int = 5000):
    """Start Flask server with logging suppressed."""
    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)

    # Suppress Flask/Werkzeug logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    # Also suppress Flask CLI warnings
    cli = sys.modules.get("flask.cli")
    if cli:
        cli.show_server_banner = lambda *args, **kwargs: None

    app = create_app(str(report_path))

    # Run with minimal output
    print(f"  Server running at http://{host}:{port}/")
    print(f"  Serving reports from: {report_path.resolve()}")
    print(f"  Press Ctrl+C to stop.\n")

    app.run(host=host, port=port, use_reloader=False, threaded=True)
