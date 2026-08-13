"""Credential resolvers for the Attribute -> CloudFlow enforcement path.

Each provider submodule turns a credential *as observed on the wire* by the
Attribute sensor into the provider-native identifiers needed to contain it.

Resolvers are pure: no network, no SDKs, no secrets retained.
"""

from __future__ import annotations

__all__ = ["bedrock"]
