"""Icewall web UI — a local FastAPI app over the scan engine.

`create_app()` builds the FastAPI application; `run()` serves it with uvicorn.
The CLI exposes it as `icewall ui`.
"""
from icewall.ui.server import create_app, run

__all__ = ["create_app", "run"]
