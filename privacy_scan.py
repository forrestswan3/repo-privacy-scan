#!/usr/bin/env python3
"""repo-privacy-scan: find personal and infrastructure data before it goes public.

Scans every blob in a git repository's full history (all branches and tags), a
plain directory (for example a static-site build folder), or a list of live URLs.
It combines built-in detectors (private IPs, Windows SIDs, emails, key material)
with a private terms file you keep outside the repository (staff names, internal
hostnames, share names, street addresses...).

Findings never print the matched text by default, so CI logs stay clean.
Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator

__version__ = "1.0.1"

# --------------------------------------------------------------------------- detectors
BUILTIN: dict[str, str] = {
    "private-ipv4": r"(?<![\d.])(?:10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})(?![\d.]*\d)",
    "windows-sid": r"\bS-1-5-21-\d{6,}-\d+-\d+(?:-\d+)?\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "aws-access-key": r"\bAKIA[0-9A-Z]{16}\b",
    "wireguard-key-assignment": r"(?im)^\s*(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{42,43}=\s*$",
    "secret-assignment": r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
}

# Emails that are safe by definition (documentation domains, GitHub noreply).
SAFE_EMAIL = re.compile(r"@(?:example\.(?:com|org|net)|[a-z0-9.-]*\.example|users\.noreply\.github\.com|noreply\.github\.com)$", re.I)
# RFC 5737 documentation ranges are not private and never flagged; nothing to allow-list.

BINARY_SNIFF = 8000


@dataclass
class Finding:
    source: str          # repo / dir / url
    location: str        # path (plus first commit for git)
    category: str        # detector name or "term"
    line: int
    fingerprint: str     # sha256 prefix of the match, so repeats can be tracked without revealing them
    match: str | None = None


@dataclass
class Detectors:
    patterns: dict[str, re.Pattern] = field(default_factory=dict)

    @classmethod
    def build(cls, terms_file: str | None = None, disable: Iterable[str] = ()) -> "Detectors":
        pats = {k: re.compile(v) for k, v in BUILTIN.items() if k not in set(disable)}
        if terms_file:
            terms = load_terms(terms_file)
            # compiled one by one so each term may carry its own inline flags, e.g. (?i)
            for i, t in enumerate(terms):
                pats[f"term#{i}"] = re.compile(t, re.I)
        return cls(pats)

    def scan_text(self, text: str) -> Iterator[tuple[str, int, str]]:
        for key, rx in self.patterns.items():
            cat = "term" if key.startswith("term#") else key
            for m in rx.finditer(text):
                hit = m.group(0)
                if cat == "email" and SAFE_EMAIL.search(hit):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                yield cat, line, hit


def load_terms(path: str) -> list[str]:
    """One term per line. Plain text is escaped; prefix a line with 're:' for a raw regex. '#' starts a comment."""
    out: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("re:"):
                pattern = s[3:]
                re.compile(pattern)  # fail fast on a bad regex
                out.append(pattern)
            else:
                out.append(r"\b" + re.escape(s) + r"\b")
    return out


def _fp(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()[:12]


def _is_binary(data: bytes) -> bool:
    return b"\0" in data[:BINARY_SNIFF]


# --------------------------------------------------------------------------- git
def _git(repo: str, *args: str, binary: bool = False):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True)
    return r.stdout if binary else r.stdout.decode("utf-8", "ignore")


def _excluded(path: str, exclude: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in exclude)


def scan_git(repo: str, det: Detectors, show: bool = False, exclude: Iterable[str] = ()) -> list[Finding]:
    """Every unique blob reachable from any ref, plus commit author/committer emails."""
    findings: list[Finding] = []
    seen: set[str] = set()
    first_commit: dict[str, str] = {}
    # map blob -> first commit that introduced it (oldest first)
    for commit in _git(repo, "rev-list", "--all", "--reverse").split():
        for line in _git(repo, "ls-tree", "-r", commit).splitlines():
            meta, _, path = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                first_commit.setdefault(parts[2] + "\0" + path, commit)
    for key, commit in first_commit.items():
        blob, path = key.split("\0", 1)
        if blob in seen or _excluded(path, exclude):
            continue
        seen.add(blob)
        data = _git(repo, "cat-file", "-p", blob, binary=True)
        if _is_binary(data):
            continue
        for cat, line, hit in det.scan_text(data.decode("utf-8", "ignore")):
            findings.append(Finding(repo, f"{path} @ {commit[:8]}", cat, line, _fp(hit), hit if show else None))
    # identities in commit metadata
    log = _git(repo, "log", "--all", "--format=%H%x09%ae%x09%ce")
    for row in log.splitlines():
        h, ae, ce = (row.split("\t") + ["", ""])[:3]
        for addr in {ae, ce}:
            if addr and not SAFE_EMAIL.search(addr):
                findings.append(Finding(repo, f"commit {h[:8]} metadata", "commit-email", 0, _fp(addr), addr if show else None))
    return findings


# --------------------------------------------------------------------------- directory
def scan_dir(root: str, det: Detectors, show: bool = False, skip: Iterable[str] = (".git", "node_modules"), exclude: Iterable[str] = ()) -> list[Finding]:
    findings: list[Finding] = []
    skip = set(skip)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if _is_binary(data):
                continue
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if _excluded(rel, exclude):
                continue
            for cat, line, hit in det.scan_text(data.decode("utf-8", "ignore")):
                findings.append(Finding(root, rel, cat, line, _fp(hit), hit if show else None))
    return findings


# --------------------------------------------------------------------------- urls
def check_urls(url_file: str, det: Detectors, show: bool = False, timeout: int = 20) -> tuple[list[Finding], list[str]]:
    """Each line: '<url> <expected-status>'. Fetches logged-out; flags wrong status and sensitive content."""
    findings: list[Finding] = []
    failures: list[str] = []
    with open(url_file, encoding="utf-8") as fh:
        rows = [l.split() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    for url, *rest in rows:
        want = int(rest[0]) if rest else 200
        status, body = _fetch(url, timeout)
        if status != want:
            failures.append(f"{url}: expected {want}, got {status}")
        for cat, line, hit in det.scan_text(body):
            findings.append(Finding(url, url, cat, line, _fp(hit), hit if show else None))
    return findings, failures


def _fetch(url: str, timeout: int) -> tuple[object, str]:
    req = urllib.request.Request(url, headers={"User-Agent": f"repo-privacy-scan/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, TimeoutError) as e:
        return f"error: {e}", ""


# --------------------------------------------------------------------------- cli
def _report(findings: list[Finding], failures: list[str], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"findings": [asdict(f) for f in findings], "url_failures": failures}, indent=2))
        return
    for f in findings:
        shown = f" -> {f.match}" if f.match is not None else ""
        where = f"{f.location}:{f.line}" if f.line else f.location
        print(f"[{f.category}] {where} (id {f.fingerprint}){shown}")
    for msg in failures:
        print(f"[url-status] {msg}")
    cats: dict[str, int] = {}
    for f in findings:
        cats[f.category] = cats.get(f.category, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(cats.items())) or "none"
    print(f"\n{len(findings)} finding(s) ({summary}); {len(failures)} URL status failure(s).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="privacy_scan", description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("git", "scan a git repo's full history"), ("dir", "scan a directory, e.g. a build folder"), ("urls", "check live URLs logged-out")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("target", help="repo path, directory, or URL list file")
        p.add_argument("--terms", help="private terms file (keep it OUT of the repo)")
        p.add_argument("--disable", action="append", default=[], choices=sorted(BUILTIN), help="turn off a built-in detector")
        p.add_argument("--show-matches", action="store_true", help="print matched text (local use only; never in CI)")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching this glob (git/dir), e.g. 'tests/*'")
    a = ap.parse_args(argv)
    det = Detectors.build(a.terms, a.disable)
    failures: list[str] = []
    if a.cmd == "git":
        findings = scan_git(a.target, det, a.show_matches, a.exclude)
    elif a.cmd == "dir":
        findings = scan_dir(a.target, det, a.show_matches, exclude=a.exclude)
    else:
        findings, failures = check_urls(a.target, det, a.show_matches)
    _report(findings, failures, a.json)
    return 1 if (findings or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
