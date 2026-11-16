"""Correlation detector for hourly-rotated logs.

Reads one or more rotated log files, merges every event onto a single
timeline, and correlates across the rotation boundary:

  * dns_tunnel  -- many long, unique subdomains queried against the same
                   external domain from one internal IP (DNS exfiltration).
  * webshell    -- a successful upload followed by an execution request
                   under /uploads/ from the same IP (upload-then-execute).

Benign look-alikes (a few failed logins followed by a success, rejected
probes answered with 403) must not alert.  Anything that is suspicious but
missing a link in the chain goes to ``needs_review`` with the gap spelled
out.

Usage:
    python detector.py <log1> [log2 ...] <out.json>
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<rest>.*)$")
SSH_FAIL = re.compile(r"sshd\[\d+\]: Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_OK = re.compile(r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")
DNS = re.compile(r"dnsmasq\[\d+\]: query\[\w+\] (?P<fqdn>\S+) from (?P<ip>[\d.]+)")
WEB = re.compile(r'nginx: (?P<ip>[\d.]+) - - "(?P<path>\S+)" (?P<status>\d{3})')

CORRELATION_WINDOW = 3600          # seconds; upload->exec / tunnel burst
DNS_MIN_QUERIES = 8                # burst size needed for a tunnel alert
DNS_MIN_LABEL_LEN = 16             # avg first-label length of tunnelled names
EXEC_RE = re.compile(r"[?&]cmd=|\.(?:php|jsp|jspx|asp|aspx|war)(?:[?]|$)", re.I)
SENSITIVE_RE = re.compile(r"^/(?:\.env|\.git|admin|wp-|phpmyadmin|config)", re.I)


def parse_ts(text: str) -> datetime:
    # log lines carry no year; a fixed year keeps ordering correct within a
    # rotation set (and across the hour boundary, which is what matters here)
    return datetime.strptime(text, "%b %d %H:%M:%S").replace(year=2026)


def parse_line(line: str, source: str, line_no: int) -> dict | None:
    m = TS.match(line)
    if not m:
        return None
    rest = m.group("rest")
    ev = {
        "ts": parse_ts(m.group("ts")),
        "timestamp": m.group("ts"),
        "file": source,
        "line": line_no,
        "message": line.rstrip("\n"),
    }
    for kind, rx in (("ssh_fail", SSH_FAIL), ("ssh_ok", SSH_OK),
                     ("dns_query", DNS), ("web", WEB)):
        mm = rx.search(rest)
        if mm:
            ev["kind"] = kind
            ev.update(mm.groupdict())
            if kind == "web":
                ev["status"] = int(ev["status"])
            return ev
    return None


def load_events(paths: list[str]) -> list[dict]:
    events: list[dict] = []
    for order, path in enumerate(paths):
        with open(path, encoding="utf-8") as fh:
            for no, line in enumerate(fh, start=1):
                ev = parse_line(line, path, no)
                if ev:
                    ev["seq"] = (ev["ts"], order, no)
                    events.append(ev)
    # merge every file onto one timeline -- this is what reconnects chains
    # that the hourly rotation split across files
    events.sort(key=lambda e: e["seq"])
    return events


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def evidence_of(events: list[dict]) -> list[dict]:
    return [
        {"file": e["file"], "line": e["line"],
         "timestamp": e["timestamp"], "event": e["message"]}
        for e in events
    ]


def parent_domain(fqdn: str) -> str:
    # tunnelled names vary only in the first label; everything below it is
    # the exfiltration domain (tis1i0....exfil.example.com -> exfil.example.com)
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[1:]) if len(parts) >= 3 else fqdn


def first_label(fqdn: str) -> str:
    return fqdn.rstrip(".").split(".")[0]


def make_finding(rule: str, events: list[dict], entities: dict, summary: str) -> dict:
    return {
        "rule": rule,
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "entities": entities,
        "evidence": evidence_of(events),
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def detect_dns_tunnel(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Burst of long, unique subdomains under one external domain per IP."""
    findings, review = [], []
    groups: dict[tuple[str, str], list[dict]] = {}
    for e in events:
        if e["kind"] == "dns_query":
            groups.setdefault((e["ip"], parent_domain(e["fqdn"])), []).append(e)

    for (ip, domain), evs in sorted(groups.items()):
        evs.sort(key=lambda e: e["seq"])
        labels = [first_label(e["fqdn"]) for e in evs]
        unique = set(labels)
        avg_len = sum(len(x) for x in labels) / len(labels)
        span = (evs[-1]["ts"] - evs[0]["ts"]).total_seconds()
        if (len(evs) >= DNS_MIN_QUERIES and len(unique) >= DNS_MIN_QUERIES
                and avg_len >= DNS_MIN_LABEL_LEN and span <= CORRELATION_WINDOW):
            findings.append(make_finding(
                "dns_tunnel", evs,
                {"ip": ip, "domain": domain, "query_count": len(evs),
                 "unique_subdomains": len(unique)},
                f"{len(evs)} long unique subdomains of {domain} from {ip} "
                f"in {int(span)}s -- DNS tunnel exfiltration",
            ))
        elif len(evs) >= 3 and avg_len >= DNS_MIN_LABEL_LEN:
            review.append({
                "rule": "dns_tunnel",
                "entities": {"ip": ip, "domain": domain},
                "evidence": evidence_of(evs),
                "missing": f"only {len(evs)} long-subdomain queries "
                           f"(threshold {DNS_MIN_QUERIES}); need more of the "
                           f"burst -- possibly rotated into a log file that "
                           f"was not provided",
            })
    return findings, review


def detect_webshell(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Successful upload, then a 2xx execution request under /uploads/."""
    findings, review = [], []
    by_ip: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "web":
            by_ip.setdefault(e["ip"], []).append(e)

    for ip, evs in sorted(by_ip.items()):
        evs.sort(key=lambda e: e["seq"])
        uploads = [e for e in evs if e["status"] < 300
                   and "upload" in e["path"].lower()
                   and not e["path"].lower().startswith("/uploads/")]
        execs = [e for e in evs if e["status"] < 300
                 and e["path"].lower().startswith("/uploads/")
                 and EXEC_RE.search(e["path"])]
        if uploads and execs:
            up = uploads[0]
            later = [x for x in execs
                     if 0 <= (x["ts"] - up["ts"]).total_seconds() <= CORRELATION_WINDOW]
            if later:
                chain = [up] + later
                findings.append(make_finding(
                    "webshell", chain,
                    {"ip": ip, "upload": up["path"],
                     "executed": [x["path"] for x in later]},
                    f"{ip} uploaded via {up['path']} then executed "
                    f"{later[0]['path']} -- upload-then-execute webshell",
                ))
                continue
        if uploads or execs:
            missing = ("no execution request under /uploads/ observed"
                       if uploads else "no preceding successful upload observed")
            review.append({
                "rule": "webshell",
                "entities": {"ip": ip},
                "evidence": evidence_of(uploads or execs),
                "missing": f"{missing}; the other half of the chain may sit "
                           f"in a rotated log file that was not provided",
            })
    return findings, review


def detect_ssh_noise(events: list[dict]) -> list[dict]:
    """Failed logins only reach needs_review, and only when the account never
    recovers -- a few failures followed by a success is a benign typo run."""
    review = []
    by_key: dict[tuple[str, str], list[dict]] = {}
    for e in events:
        if e["kind"] in ("ssh_fail", "ssh_ok"):
            by_key.setdefault((e["ip"], e["user"]), []).append(e)
    for (ip, user), evs in sorted(by_key.items()):
        evs.sort(key=lambda e: e["seq"])
        fails = [e for e in evs if e["kind"] == "ssh_fail"]
        ok_after = any(e["kind"] == "ssh_ok" for e in evs
                       if fails and e["ts"] > fails[-1]["ts"])
        if len(fails) >= 5 and not ok_after:
            review.append({
                "rule": "ssh_bruteforce",
                "entities": {"ip": ip, "user": user},
                "evidence": evidence_of(fails),
                "missing": "no successful login recorded after the failures; "
                           "cannot confirm whether the password was guessed",
            })
    return review


def detect_rejected_probes(events: list[dict]) -> list[dict]:
    """Sensitive-path probes that were all rejected: worth a look, not an alert."""
    review = []
    by_ip: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "web" and e["status"] == 403 and SENSITIVE_RE.search(e["path"]):
            by_ip.setdefault(e["ip"], []).append(e)
    for ip, evs in sorted(by_ip.items()):
        evs.sort(key=lambda e: e["seq"])
        review.append({
            "rule": "recon_probe",
            "entities": {"ip": ip, "paths": [e["path"] for e in evs]},
            "evidence": evidence_of(evs),
            "missing": "every probe was answered 403; no 2xx response or "
                       "follow-up execution observed, so compromise cannot "
                       "be confirmed from these logs",
        })
    return review


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def scan(paths: list[str]) -> dict:
    events = load_events(paths)
    findings, review = [], []
    for detector in (detect_dns_tunnel, detect_webshell):
        f, r = detector(events)
        findings.extend(f)
        review.extend(r)
    review.extend(detect_ssh_noise(events))
    review.extend(detect_rejected_probes(events))
    findings.sort(key=lambda f: f["first_seen"])
    return {"findings": findings, "needs_review": review}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log1> [log2 ...] <out.json>")
        return 2
    *logs, out = sys.argv[1:]
    result = scan(logs)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
