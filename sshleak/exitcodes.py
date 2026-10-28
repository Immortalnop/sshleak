"""Process exit codes. Every command ends with exactly one of these."""

from enum import IntEnum


class ExitCode(IntEnum):
    CLEAN = 0  # nothing at or above --fail-on
    FINDINGS = 1  # findings at or above --fail-on
    INSUFFICIENT = 2  # evidence insufficient for requested checks
    ENVIRONMENT = 3  # environment or invocation error
    SAFETY = 4  # safety refusal
    INTERNAL = 5  # internal error (never silent)
