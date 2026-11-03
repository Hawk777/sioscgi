"""Implements the SCGI protocol."""

import importlib.metadata

__all__ = ["request", "response"]  # pyright: ignore [reportUnsupportedDunderAll]
__version__ = importlib.metadata.version("sioscgi")
