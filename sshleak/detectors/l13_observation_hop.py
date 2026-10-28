"""L13 Multiplexed or jump-host path hides observation point."""

from __future__ import annotations

from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity
from sshleak.flows.tracker import SSH_CLIENT_PROCS, SSH_SERVER_PROCS


class L13ObservationHop(Detector):
    meta = DetectorMeta(
        id="L13",
        title="Multiplexed or jump-host path hides observation point",
        short="other hop",
        severity=Severity.INFO,
        meaning="This flow is a hop (a local port forward, jump host or proxy), not the client's own "
        "connection, so timing seen here is shaped by the forwarder.",
        signal="Owning processes of the flow's endpoints: a server side owned by an ssh client (local "
        "forward / -J), or a client side owned by a non-ssh process (ProxyCommand helper).",
        min_evidence="Process information for at least one endpoint (live scan, same user or root).",
        statistic="Process-name rule.",
        false_positive_guard="Skipped when process information is unavailable (pcap input, other users).",
        fix="Re-run the scan at the client's own interface or host.",
        timing=False,
        cases=("C8",),
    )

    def run(self, ctx) -> DetectorResult:
        m = ctx.meta
        if not m.process_info_available or (m.client_proc is None and m.server_proc is None):
            return self.skipped("process information unavailable (pcap input or another user's flow)")
        srv, cli = m.server_proc, m.client_proc
        ev = {"client_process": cli.name if cli else None, "server_process": srv.name if srv else None}
        if srv is not None and srv.name in SSH_CLIENT_PROCS:
            return self.fired(0.85, "server side is an ssh client's forwarded port (jump host / -L hop)", ev)
        if cli is not None and cli.name not in SSH_CLIENT_PROCS and cli.name not in SSH_SERVER_PROCS:
            return self.fired(0.7, f"connection made by {cli.name!r}, not ssh (proxy hop)", ev)
        return self.not_fired("direct ssh client to ssh server", ev)
