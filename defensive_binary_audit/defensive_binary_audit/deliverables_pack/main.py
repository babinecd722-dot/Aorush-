#!/usr/bin/env python3
"""
Section 7: Main Entry Point — Deliverables Packaging

Builds deliverables/ package and opens HTML presentation in browser.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from defensive_binary_audit.deliverables_pack.config_manager import DeliverablesConfigManager
from defensive_binary_audit.deliverables_pack.core_packager import DeliverablePackager
from defensive_binary_audit.deliverables_pack.io_handler import DeliverablesOutputHandler
from defensive_binary_audit.deliverables_pack.logging_diagnostics import get_deliverables_logger


def _serve_and_open(html_path: Path, port: int = 8765) -> None:
    root = html_path.parent.resolve()
    url = f"http://127.0.0.1:{port}/{html_path.name}"

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    webbrowser.open(url)
    get_deliverables_logger().info("Presentation served at %s (Ctrl+C to stop server)", url)
    try:
        while thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


def run_deliverables_packaging(
    patch_artifacts_dir: Path = Path("patch_artifacts"),
    deliverables_dir: Path = Path("deliverables"),
    pipeline_report_id: str | None = None,
    open_browser: bool = True,
    serve_port: int = 8765,
) -> int:
    logger = get_deliverables_logger()
    logger.info("Building deliverables package from %s", patch_artifacts_dir)

    result = DeliverablePackager(deliverables_dir).build(
        patch_artifacts_dir=patch_artifacts_dir,
        pipeline_report_id=pipeline_report_id,
    )
    summary = DeliverablesOutputHandler().write_summary(result, deliverables_dir)

    logger.info("Reconstructed PE: %s", result.manifest.reconstructed_pe_path)
    logger.info("HTML report: %s", result.html_path)
    logger.info("Summary: %s", summary)
    logger.info("Screenshots: %d", len(result.manifest.screenshot_paths))

    print("\n" + "=" * 72)
    print("  DELIVERABLES PACKAGE — READY FOR SECURITY TEAM")
    print("=" * 72)
    print(f"  PE export:     {result.manifest.reconstructed_pe_path}")
    print(f"  HTML report:   {result.html_path}")
    print(f"  Manifest:      {deliverables_dir / 'MANIFEST.json'}")
    print(f"  Screenshots:   {deliverables_dir / 'screenshots'}/ ({len(result.manifest.screenshot_paths)} files)")
    print(f"  Patches (RVA): {len(result.patches)}")
    print("=" * 72 + "\n")

    if open_browser:
        html = Path(result.html_path)
        try:
            opened = webbrowser.open(f"file://{html.resolve()}")
            if not opened:
                _serve_and_open(html, serve_port)
        except Exception:
            _serve_and_open(html, serve_port)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="deliverables-pack",
        description="Export reconstructed PE and generate security presentation HTML",
    )
    parser.add_argument(
        "-a", "--patch-artifacts",
        type=Path,
        default=Path("patch_artifacts"),
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("deliverables"),
    )
    parser.add_argument("--pipeline-id", default=None)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    sys.exit(run_deliverables_packaging(
        patch_artifacts_dir=args.patch_artifacts,
        deliverables_dir=args.output_dir,
        pipeline_report_id=args.pipeline_id,
        open_browser=not args.no_browser,
        serve_port=args.port,
    ))


if __name__ == "__main__":
    main()
