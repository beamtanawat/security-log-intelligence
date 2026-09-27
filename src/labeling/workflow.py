"""Append-only Stage 2.1 review workflow transitions."""

from __future__ import annotations


class InvalidTransition(ValueError):
    """Raised when a review state transition violates the plan."""


_TRANSITIONS: dict[tuple[str, str], frozenset[str]] = {
    ("NONE", "PENDING"): frozenset({"WORKFLOW_ENGINE"}),
    ("PENDING", "IN_REVIEW"): frozenset({"PRIMARY_REVIEWER"}),
    ("IN_REVIEW", "REVIEWED"): frozenset({"PRIMARY_REVIEWER"}),
    ("REVIEWED", "RESOLVED"): frozenset({"WORKFLOW_ENGINE"}),
    ("REVIEWED", "NEEDS_ADJUDICATION"): frozenset({"WORKFLOW_ENGINE"}),
    ("NEEDS_ADJUDICATION", "ADJUDICATING"): frozenset({"HUMAN_ADJUDICATOR"}),
    ("ADJUDICATING", "RESOLVED"): frozenset({"HUMAN_ADJUDICATOR"}),
    ("PENDING", "CLOSED_UNRESOLVED"): frozenset({"REVIEW_ADMINISTRATOR"}),
    ("IN_REVIEW", "CLOSED_UNRESOLVED"): frozenset({"REVIEW_ADMINISTRATOR"}),
    ("NEEDS_ADJUDICATION", "CLOSED_UNRESOLVED"): frozenset({"REVIEW_ADMINISTRATOR"}),
    ("ADJUDICATING", "CLOSED_UNRESOLVED"): frozenset({"REVIEW_ADMINISTRATOR"}),
    ("RESOLVED", "SUPERSEDED"): frozenset({"CORRECTION_OFFICER"}),
    ("CLOSED_UNRESOLVED", "SUPERSEDED"): frozenset({"CORRECTION_OFFICER"}),
}


def transition(current: str, new: str, *, actor_type: str) -> str:
    allowed = _TRANSITIONS.get((current, new), frozenset())
    if actor_type not in allowed:
        raise InvalidTransition(f"invalid transition {current}->{new} for {actor_type}")
    return new
