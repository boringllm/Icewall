#!/usr/bin/env python
"""Launch the Icewall web UI with one command:

    python run.py

Same thing as `icewall ui`, but runs straight from a source checkout (no
`pip install` needed) and opens your browser. Options:

    python run.py --port 9000            # serve on a different port
    python run.py --host 0.0.0.0         # listen on all interfaces
    python run.py --no-open              # don't open a browser
    python run.py --workshop-dir DIR     # where the dashboard reads sessions from
    python run.py --import icewall.yaml  # import a config file as a preset, then serve
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from a plain checkout, before/without `pip install`.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the Icewall web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--port", "-p", type=int, default=8765, help="Port to serve on.")
    parser.add_argument("--workshop-dir", default=".icewall",
                        help="Workshop root the dashboard reads sessions from.")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser.")
    parser.add_argument("--import", dest="import_config", metavar="PATH",
                        help="Import a config file (e.g. icewall.yaml) as a preset, then serve.")
    parser.add_argument("--import-name", help="Name for the imported preset (default: file stem).")
    args = parser.parse_args()

    try:
        from icewall.ui import run
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", None) or "a dependency"
        print(
            f"The Icewall UI needs packages that aren't installed (missing: {missing}).\n"
            "Install them with either:\n"
            '    pip install "fastapi>=0.110" "uvicorn>=0.27"\n'
            '    pip install -e ".[ui]"',
            file=sys.stderr,
        )
        raise SystemExit(1)

    if args.import_config:
        from icewall.ui.presets import PresetStore

        store = PresetStore(f"{args.workshop_dir}/presets")
        try:
            info = store.import_file(args.import_config, args.import_name)
        except Exception as exc:
            print(f"Could not import {args.import_config}: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Imported preset '{info['name']}' from {args.import_config}")

    url = f"http://{args.host}:{args.port}/"
    print(f"Icewall UI on {url}  (Ctrl-C to stop)")
    if not args.no_open:
        import threading
        import webbrowser

        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        run(host=args.host, port=args.port, workshop_root=args.workshop_dir)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
