"""Error types that map onto exit codes."""

from __future__ import annotations

from sshleak.exitcodes import ExitCode


class SshleakError(Exception):
    exit_code: ExitCode = ExitCode.INTERNAL

    def __init__(self, message: str, *, fix: str | None = None, case: str | None = None):
        super().__init__(message)
        self.message = message
        self.fix = fix
        self.case = case


class EnvironmentProblem(SshleakError):
    """Capture rights, missing interface, missing tools, unreadable input."""

    exit_code = ExitCode.ENVIRONMENT


class SafetyRefusal(SshleakError):
    """The safety guard refused the request."""

    exit_code = ExitCode.SAFETY
