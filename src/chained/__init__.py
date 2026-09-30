"""Stage 2.4A chained-feature contracts and leakage-safe context planning."""

from .contracts import (
    BASE_FEATURES,
    CHAIN_SOURCE_FEATURES,
    build_chain_contract,
    build_contexts,
    validate_inputs,
)

__all__ = [
    "BASE_FEATURES",
    "CHAIN_SOURCE_FEATURES",
    "build_chain_contract",
    "build_contexts",
    "validate_inputs",
]
