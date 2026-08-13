"""Enforcement adapter: authenticates Attribute alerts and forwards to CloudFlow.

``signature`` and ``policy`` are pure and unit-tested. ``handler`` holds the
Lambda entry point and all AWS/network I/O.
"""

from __future__ import annotations

__all__ = ["policy", "signature"]
