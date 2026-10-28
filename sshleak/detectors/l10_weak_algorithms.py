"""L10 Weak cipher or MAC family."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib import resources

from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity
from sshleak.kex import IMPLICIT_MAC


@lru_cache(maxsize=1)
def algorithm_lists() -> dict:
    return tomllib.loads((resources.files("sshleak.data") / "algorithms.toml").read_text())


class L10WeakAlgorithms(Detector):
    meta = DetectorMeta(
        id="L10",
        title="Weak cipher or MAC family",
        short="weak algorithms",
        severity=Severity.MEDIUM,
        meaning="The negotiated cipher or MAC is a deprecated family, or the mode is open to prefix "
        "truncation (Terrapin, CVE-2023-48795) because strict key exchange is not in use.",
        signal="Negotiated algorithm names from the cleartext KEXINIT exchange.",
        min_evidence="Both KEXINIT messages seen (not a late-join flow).",
        statistic="RFC 4253 7.1 negotiation against the reference lists in data/algorithms.toml.",
        false_positive_guard="AEAD ciphers carry their own MAC and are not judged by the MAC list.",
        fix="Prefer chacha20-poly1305@openssh.com or aes*-gcm@openssh.com with strict KEX (OpenSSH 9.6+ "
        "on both sides); remove CBC, 3DES, MD5/SHA1-96 and umac-64 from Ciphers/MACs.",
        timing=False,
        cases=("V6", "F5"),
    )

    def run(self, ctx) -> DetectorResult:
        neg = ctx.meta.negotiated
        if neg is None:
            return self.skipped("negotiated algorithms unknown (late-join or handshake not captured)")
        lists = algorithm_lists()
        weak_c = set(lists["ciphers"]["weak"])
        weak_m = set(lists["macs"]["weak"])
        terr = lists["terrapin"]
        reasons: list[str] = []
        for direction, enc, mac in (("c2s", neg.enc_c2s, neg.mac_c2s), ("s2c", neg.enc_s2c, neg.mac_s2c)):
            if enc in weak_c:
                reasons.append(f"{direction} cipher {enc}")
            if mac and mac != IMPLICIT_MAC and mac in weak_m:
                reasons.append(f"{direction} MAC {mac}")
            if not neg.strict_kex and enc and (
                enc in terr["affected_ciphers"]
                or (terr["affected_cbc_with_etm"] and enc.endswith("-cbc") and (mac or "").endswith("-etm@openssh.com"))
            ):
                reasons.append(f"{direction} {enc} without strict KEX (Terrapin, CVE-2023-48795)")
        ev = {
            "cipher_c2s": neg.enc_c2s, "cipher_s2c": neg.enc_s2c,
            "mac_c2s": neg.mac_c2s, "mac_s2c": neg.mac_s2c,
            "strict_kex": neg.strict_kex,
        }
        if not reasons:
            return self.not_fired("negotiated cipher and MAC are current", ev)
        ev["reasons"] = sorted(set(reasons))
        return self.fired(0.95, "; ".join(sorted(set(reasons))), ev)
