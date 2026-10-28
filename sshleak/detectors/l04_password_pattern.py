"""L4 Password-entry pattern visible."""

from __future__ import annotations

import numpy as np
from scipy import stats as sps

from sshleak.analysis.stats import confidence, r
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


def _runs(mask: np.ndarray, breaks: np.ndarray, min_len: int) -> list[tuple[int, int]]:
    """Maximal [start, end) runs of True in mask, split where breaks is True."""
    out = []
    i, n = 0, len(mask)
    while i < n:
        if not mask[i]:
            i += 1
            continue
        j = i + 1
        while j < n and mask[j] and not breaks[j]:
            j += 1
        if j - i >= min_len:
            out.append((i, j))
        i = j
    return out


class L4PasswordPattern(Detector):
    meta = DetectorMeta(
        id="L4",
        title="Password-entry pattern visible",
        short="password typing",
        severity=Severity.HIGH,
        meaning="While echo is off (sudo, su, read -s) keystrokes get no echo. If that shows in the "
        "traffic, an observer learns when a secret is typed, its length and its keystroke timing.",
        signal="A run of keystrokes with no server reply inside the echo window, then a burst on Enter; or a "
        "run whose replies arrive much faster than real echoes (simulated echo distinguishable by latency).",
        min_evidence="min_packets keystrokes, an echo rate elsewhere of at least min_echo_rate, and a run of "
        "min_run (no reply) or min_latency_run (fast reply) keystrokes.",
        statistic="Union-bound probability of such a no-reply run under the session's miss rate; for "
        "simulated echo, the median reply latency of min_latency_run consecutive keystrokes over the "
        "session median (below latency_ratio_max), confirmed by a one-sided Mann-Whitney U test.",
        false_positive_guard="Requires a high echo rate elsewhere; the latency test is not applied under "
        "obfuscation (chaff PONGs are as fast as simulated echo); constant server output (tmux/screen "
        "redraw, S6) lowers confidence.",
        fix="Use key or agent authentication instead of typing secrets in a remote prompt; upgrade to a fixed "
        "OpenSSH so chaff and simulated echo hide echo-off typing.",
        threshold_keys=("L4.*", "echo.*"),
        cases=("S6",),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        t4 = ctx.th.L4
        g = ctx.th.global_
        replied = ia.reply_count > 0
        n = ia.n_ticks
        breaks = np.zeros(n, dtype=bool)
        if n > 1:
            gaps = np.diff(ia.tick_t)
            breaks[1:] = (gaps > ctx.th.ticks.max_run_gap_s) | (ia.tick_seg[1:] != ia.tick_seg[:-1])
        quiet_runs = _runs(~replied, breaks, t4.min_run)
        in_quiet = np.zeros(n, dtype=bool)
        for a, b in quiet_runs:
            in_quiet[a:b] = True
        rest = ~in_quiet
        echo_rate = float(replied[rest].mean()) if rest.any() else 0.0
        miss = max(1.0 - echo_rate, 1e-6)
        # A quiet run counts when output resumes right after it: at least two units of
        # server data within the response window after the run's last keystroke (Enter).
        st, ss = ia.server_t, ia.server_size
        cum = np.concatenate([[0], np.cumsum(ss)])
        resp = ctx.th.echo.response_window_s
        confirmed = []
        for a, b in quiet_runs:
            t_end = ia.tick_t[b - 1]
            lo = np.searchsorted(st, t_end, side="right")
            hi = np.searchsorted(st, t_end + resp, side="right")
            if cum[hi] - cum[lo] >= 2 * (ia.unit or 1):
                confirmed.append((a, b))
        p_quiet = min(1.0, n * miss ** t4.min_run) if confirmed else 1.0

        lat = ia.reply_latency
        finite = np.isfinite(lat)
        fast_runs: list[tuple[int, int]] = []
        p_fast = 1.0
        min_ratio = None
        k = t4.min_latency_run
        # Under obfuscation every chaff tick gets an immediate PONG, which is as fast as
        # simulated echo, so the latency test only applies without a fixed send cadence.
        latency_applicable = not ia.cadence.present
        if latency_applicable and finite.sum() >= ctx.th.global_.min_packets and n >= k:
            # Simulated echo (sshd's IGNORE while echo is off) is sent before the
            # shell sees the key, so it arrives faster than a real echo. Single
            # latencies are noisy; compare the median of k consecutive keystrokes
            # with the session median.
            med = float(np.median(lat[finite]))
            win = np.lib.stride_tricks.sliding_window_view(lat, k)
            brk = np.lib.stride_tricks.sliding_window_view(breaks, k)[:, 1:].any(axis=1)
            ok = np.isfinite(win).all(axis=1) & ~brk
            ratios = np.full(len(win), np.inf)
            ratios[ok] = np.median(win[ok], axis=1) / med
            if ok.any():
                min_ratio = float(ratios[ok].min())
            fast = np.zeros(n, dtype=bool)
            for i in np.flatnonzero(ratios < t4.latency_ratio_max):
                fast[i : i + k] = True
            fast_runs = _runs(fast, breaks, k)
            if fast_runs:
                inside = np.zeros(n, dtype=bool)
                for a, b in fast_runs:
                    inside[a:b] = True
                x, y = lat[inside & finite], lat[~inside & finite]
                if len(x) >= 3 and len(y) >= 3:
                    p_fast = float(sps.mannwhitneyu(x, y, alternative="less").pvalue)
        caps = ("redraw_noise",) if ia.server_noise_ratio > t4.redraw_noise_max else ()
        ev = {
            "keystroke_ticks": n,
            "echo_rate": r(echo_rate, 3),
            "echo_window_ms": r(ia.echo_window_s * 1000, 2),
            "no_reply_runs": len(confirmed),
            "longest_no_reply_run": max((b - a for a, b in confirmed), default=0),
            "fast_reply_runs": len(fast_runs),
            "longest_fast_reply_run": max((b - a for a, b in fast_runs), default=0),
            "min_window_latency_ratio": r(min_ratio, 3),
            "latency_test": "applied" if latency_applicable else "not applicable under obfuscation (chaff replies are fast)",
            "server_noise_ratio": r(ia.server_noise_ratio, 3),
        }
        if echo_rate < t4.min_echo_rate:
            return self.insufficient(f"keystrokes are echoed only {echo_rate:.0%} of the time; echo-off runs cannot be told apart", ev)
        p = min(p_quiet, p_fast)
        if confirmed and p_quiet <= g.alpha:
            run_keys = sum(b - a for a, b in confirmed)
            conf = confidence(min(1.0, run_keys / (2 * t4.min_run)), n, g.confidence_n0)
            summary = f"{len(confirmed)} echo-off run(s), longest {ev['longest_no_reply_run']} keystrokes, then a burst on Enter"
            return self.fired(conf, summary, ev, p_quiet, caps)
        if fast_runs and p_fast <= g.alpha:
            run_keys = sum(b - a for a, b in fast_runs)
            conf = confidence(min(1.0, run_keys / (2 * t4.min_latency_run)), n, g.confidence_n0) * 0.8
            summary = f"{len(fast_runs)} run(s) of replies faster than echo (simulated echo), longest {ev['longest_fast_reply_run']} keystrokes"
            return self.fired(conf, summary, ev, p_fast, caps)
        return self.not_fired("no echo-off typing pattern", ev, p)
