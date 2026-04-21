"""Fold rules package."""

from typing import Optional


class BaseRule:
    """Base class for fold rules."""
    name: str = "base"

    def match(self, finding: dict) -> Optional[dict]:
        """Return match dict with key, root_cause, fix_target, recommendation, reason.
        Return None if this rule doesn't apply."""
        raise NotImplementedError
