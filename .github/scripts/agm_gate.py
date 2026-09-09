#!/usr/bin/env python3
"""AGM gate: enforce agm.json on a pull request.

Computes the risk zone from the changed files, checks the PR body for the
declared zone and the required evidence sections, including merge authorization,
and scans the body for identifiers that should have been redacted.
Writes the review packet to the job summary. Exits non-zero when a gate
fails.

This script is run by `.github/workflows/agm.yml` on `pull_request_target`,
which means it is always the copy on the BASE branch — never the copy in
the pull request. It reads `agm.json` from the tree it lives in, for the
same reason. It never executes, checks out, or sources anything from the
pull request: the changed-file list and the body are DATA.

Inputs (environment):
  BODY                 pull-request body (data; never a shell command)
  CHANGED_FILES_FILE   path to a NUL-separated list of changed paths, as
                       produced by `git diff -z --name-only BASE...HEAD`.
                       This is what CI uses.
  CHANGED_FILES        newline-separated list, for running the gate by
                       hand. Mutually exclusive with CHANGED_FILES_FILE.
  GITHUB_STEP_SUMMARY  summary file path (optional)

There is deliberately no fallback that derives the changed files from the
working tree. Under `pull_request_target` the working tree IS the base
branch, so such a fallback would diff base against base, produce an empty
list, compute zone `low`, and pass every gate silently. A gate that cannot
see the change refuses to run instead.

Exit codes:
  0  every mechanical gate passes
  1  a gate failed — the contribution is not ready
  2  the gate could not run (missing input, unreadable manifest). Never a
     pass: a broken gate must not look like a green one.

`.github/scripts/test_agm_gate.py` covers all of the above and runs in
`ci.yml` on every push and pull request. This file is in agm.json's
CRITICAL zone; when you change its behaviour, change that suite with it.
"""

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

SEVERITY = ["low", "medium", "high", "critical"]

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "agm.json"


def die(message):
    """Refuse to run. Exit 2 so a broken gate is never mistaken for a pass."""
    print(f"agm_gate: {message}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------


def load_manifest():
    try:
        text = MANIFEST_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        die(f"cannot read the manifest at {MANIFEST_PATH}: {exc}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        die(f"{MANIFEST_PATH} is not valid JSON: {exc}")


def changed_files():
    path = os.environ.get("CHANGED_FILES_FILE")
    inline = os.environ.get("CHANGED_FILES")

    # Presence, not truthiness, decides which source was specified. A
    # workflow expression that resolves to nothing exports the variable as an
    # empty string, and reading that as "unset" would let the OTHER source
    # win silently — or, with neither usable, fall through to an empty diff.
    # An empty value is a plumbing failure and is refused as one.
    if path is not None and inline is not None:
        die(
            "CHANGED_FILES_FILE and CHANGED_FILES are both set; refusing to "
            "guess which one describes the pull request."
        )

    if path is not None:
        if not path.strip():
            die(
                "CHANGED_FILES_FILE is set but empty. Something upstream of "
                "this step produced no path — refusing to fall back to a "
                "different source or to an empty diff."
            )
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            die(f"cannot read CHANGED_FILES_FILE ({path}): {exc}")
        # `git diff -z` separates paths with NUL and never quotes them, so a
        # path containing a newline stays one path.
        parts = raw.split("\0")
    elif inline is not None:
        parts = inline.splitlines()
    else:
        die(
            "no changed-file list. Set CHANGED_FILES_FILE to the output of "
            "`git diff -z --name-only BASE...HEAD`, or CHANGED_FILES to a "
            "newline-separated list. There is no default: an empty list "
            "computes zone `low` and would pass every gate."
        )

    files = [p for p in parts if p.strip()]
    if not files:
        die(
            "the changed-file list is empty. A pull request always changes at "
            "least one file, so this is a plumbing failure, not a zone-`low` "
            "change — refusing to pass a gate that saw nothing."
        )
    return files


# ---------------------------------------------------------------------------
# zones
# ---------------------------------------------------------------------------


def file_zone(path, zones):
    best = "low"
    for zone in zones:
        if any(fnmatch.fnmatch(path, pat) for pat in zone["paths"]):
            if SEVERITY.index(zone["level"]) > SEVERITY.index(best):
                best = zone["level"]
    return best


# ---------------------------------------------------------------------------
# redaction scan
# ---------------------------------------------------------------------------
#
# GOVERNANCE.md requires evidence to be redacted evidence: `acct_REDACTED`,
# `user_REDACTED`, `email_REDACTED`, and no token values. This scan fails the
# gate when the body carries the real thing instead. It runs for every zone,
# including `low` — a leaked credential is not a documentation change.
#
# Precision matters more than recall here. A gate that fires on `user_id` (a
# phrase that ships inside .github/PULL_REQUEST_TEMPLATE.md, so it appears in
# nearly every real body) would be turned off within a week. So a match must
# look like a machine-generated VALUE, not like prose or a field name.

PLACEHOLDERS = frozenset({"acct_REDACTED", "user_REDACTED", "email_REDACTED"})

# `acct_`/`user_` followed by one unbroken run of value characters. The
# trailing lookahead means `user_account_identifier` does not match at all
# (the suffix runs into another `_`), while `user_id` matches and is then
# rejected as prose by _looks_like_a_value.
ID_RE = re.compile(r"(?<![A-Za-z0-9_-])(acct|user)_([A-Za-z0-9][A-Za-z0-9-]*)(?![A-Za-z0-9_-])")

# This matches the coarse shape only — `<word>@<dotted.labels>`. It is not
# the decision; _domain_has_a_real_tld below is. See the note there.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
)

# A JWT is three dot-separated base64url segments.
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9._-])([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9._-])"
)
# The base64url of a JWT header always starts `eyJ` (`{"`). This catches a
# token pasted without its signature, which the three-segment shape misses.
# `tests/live.rs` redacts on the same prefix.
JWT_HEAD_RE = re.compile(r"(?<![A-Za-z0-9._-])eyJ[A-Za-z0-9_-]{13,}")

HEADING_RE = re.compile(r"^#{1,6}\s+\S")

# A fenced code block opens with three or more backticks or tildes, indented
# by at most three spaces (CommonMark §4.5), and closes with a run of the
# same character, at least as long, alone on its line.
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")

# RFC 2606 / RFC 6761 reserved names cannot belong to a real person, and
# `noreply@` addresses are not personal mailboxes. Everything else counts.
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org", "example.edu"})
# Every entry starts with a dot on purpose: it is a DNS-label boundary, not a
# string suffix. `noreply.github.com` without it would also match
# `evilnoreply.github.com`, a name the reserved rule says nothing about.
# `_email_is_reserved` matches the entry with its leading dot removed too, so
# the apex name itself (`invalid`, `noreply.github.com`) is still reserved.
RESERVED_SUFFIXES = (".example", ".invalid", ".test", ".localhost", ".noreply.github.com")
NOREPLY_LOCALS = frozenset({"noreply", "no-reply"})

KIND_ID = "account/user identifier"
KIND_EMAIL = "email address"
KIND_JWT = "JWT-shaped token"

REMEDY = {
    KIND_ID: (
        "Replace it with `acct_REDACTED` / `user_REDACTED` and re-run this check."
    ),
    KIND_EMAIL: "Replace it with `email_REDACTED` and re-run this check.",
    KIND_JWT: (
        "Remove it. A token in a pull-request body is a leaked credential — it is "
        "now in the repository's event history and in this job's log. Treat it as "
        "compromised and rotate it at the issuer."
    ),
}


def _looks_like_a_value(text):
    """True when a string looks machine-generated rather than written.

    Three signals, any one of which is enough. Identifiers are long, and they
    are built from an alphabet a writer does not reach for: a digit, or mixed
    case inside one word. Failing both, sheer length (16+ unbroken characters)
    is itself the signal.
    """
    if len(text) < 8:
        return False
    if any(c.isdigit() for c in text):
        return True
    if any(c.isupper() for c in text) and any(c.islower() for c in text):
        return True
    return len(text) >= 16


def _domain_has_a_real_tld(domain):
    """True when the last label could be a top-level domain.

    A version pin and an email address share one shape — `word@dotted.labels`
    — so `actions/checkout@v4.2.2`, `Swatinem/rust-cache@v2.7.8`,
    `askcodex@0.1.0`, `typescript@5.4.2` and `ubuntu@22.04` all reach EMAIL_RE.
    Telling them apart on the local part is hopeless; the last label decides
    it. In the DNS root zone every top-level domain is either all ASCII
    letters (`com`, `dev`, `museum`) or a punycode `xn--` label, and RFC 1123
    §2.1 forbids an all-numeric one precisely so a name cannot be mistaken
    for an address literal. A version's last segment is the opposite: `2`,
    `8`, `0`, `04`, or something like `0-beta` that is not a word either.

    So this drops every version pin without weakening the catch on a real
    address, whose TLD is a real TLD by construction. The one address shape
    it does give up is the IP literal, `person@203.0.113.9` — indistinguishable
    from the four-segment version `4.2.2.0`, and the file's rule above
    ("precision matters more than recall") settles that trade the same way.
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    if len(tld) < 2:
        return False
    return tld.isalpha() or tld.startswith("xn--")


def _email_is_reserved(local, domain):
    domain = domain.lower()
    if local.lower() in NOREPLY_LOCALS:
        return True
    if domain in RESERVED_DOMAINS:
        return True
    # `s[1:]` is the apex of the reserved suffix; `s` keeps the leading dot so
    # the match is on a label boundary and not on any name that merely ends in
    # those characters.
    return any(domain == s[1:] or domain.endswith(s) for s in RESERVED_SUFFIXES)


def _kinds_in_line(line):
    """Which kinds of unredacted identifier appear in one line."""
    kinds = set()

    for match in ID_RE.finditer(line):
        token = match.group(0)
        if token in PLACEHOLDERS:
            continue
        if _looks_like_a_value(match.group(2)):
            kinds.add(KIND_ID)

    for match in EMAIL_RE.finditer(line):
        local, domain = match.group(1), match.group(2)
        if not _domain_has_a_real_tld(domain):
            continue  # a version pin, not an address — see the function.
        if not _email_is_reserved(local, domain):
            kinds.add(KIND_EMAIL)

    if JWT_HEAD_RE.search(line):
        kinds.add(KIND_JWT)
    else:
        for match in JWT_RE.finditer(line):
            first, second = match.group(1), match.group(2)
            if _looks_like_a_value(first) and _looks_like_a_value(second):
                kinds.add(KIND_JWT)

    return kinds


def scan_for_leaks(body):
    """Report unredacted identifiers as (kind, line number, section).

    The matched text is never returned, printed, or written to the job
    summary: naming it would leak it a second time, into a log the whole
    world can read.
    """
    leaks = []
    seen = set()
    section = "(before the first heading)"
    fence = None  # (character, length) of the open code fence, or None
    for lineno, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()

        # Unconditional, and deliberately outside the fence handling below: a
        # pasted transcript lives INSIDE a fence, so that is exactly where a
        # leak is most likely. Only the heading attribution treats fences
        # specially.
        kinds = sorted(_kinds_in_line(line))

        rail = FENCE_RE.match(line)
        if fence is None:
            if rail:
                fence = (rail.group(1)[0], len(rail.group(1)))
            elif HEADING_RE.match(stripped):
                # The heading text is quoted back as the location of a leak, so
                # it must not itself be quotable. A heading like
                # `## Transcript for acct_...` would otherwise publish the value
                # in every later message.
                section = (
                    f"(the heading at line {lineno}, which itself needs redaction)"
                    if kinds
                    else stripped
                )
        else:
            # A closing rail is the same character, at least as long, and alone
            # on its line. `# a shell comment` inside the block is not a
            # heading, so `section` keeps naming the last real one — pointing
            # the contributor at the part of the body they actually wrote.
            char, length = fence
            if (
                rail
                and rail.group(1)[0] == char
                and len(rail.group(1)) >= length
                and stripped == rail.group(1)
            ):
                fence = None

        for kind in kinds:
            key = (kind, lineno)
            if key in seen:
                continue
            seen.add(key)
            leaks.append((kind, lineno, section))
    return leaks


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


def authorization_has_content(body, heading):
    """Require bounded visible prose, not proof of identity or permission."""
    # Comments and fenced examples are not submitted evidence. An unclosed
    # comment is a template fragment, not authorization prose.
    body = re.sub(r"<!--.*?(?:-->|$)", "", body, flags=re.DOTALL)
    active = False
    fence = None
    prose = []
    for line in body.splitlines():
        stripped = line.strip()
        marker = re.match(r"^(`{3,}|~{3,})", stripped)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        if stripped == heading:
            if active:
                break
            active = True
            continue
        if active and re.match(r"^#{1,2}(?:\s|$)", stripped):
            break
        if not active or stripped.startswith("#"):
            continue
        normalized = stripped.strip("-*_` []").casefold()
        if re.match(r"^(?:todo|tbd|n/a|none|pending|placeholder)(?:\W|$)", normalized):
            continue
        # Angle placeholders and unchecked template boxes cannot supply words.
        stripped = re.sub(r"<[^>]*>|\[[ xX]?\]", "", stripped)
        prose.append(stripped)
    words = re.findall(r"[^\W_]+", " ".join(prose), flags=re.UNICODE)
    words = [word for word in words if word.casefold() not in
             {"todo", "tbd", "placeholder", "maintainer", "scope"}]
    return len(words) >= 3


def evidence_failures(manifest, body, computed):
    failures = []

    m = re.search(r"Risk zone:\s*(\w+)", body)
    declared = m.group(1).lower() if m else None
    if declared is None:
        failures.append("Declare the risk zone in the PR body (`Risk zone: ...`).")
    elif declared != computed:
        failures.append(
            f"Declared zone `{declared}` does not match computed zone `{computed}`."
        )

    required = manifest["evidence"][computed]
    sections = manifest["sections"]
    for key in required:
        spec = sections[key]
        if spec["heading"] not in body:
            failures.append(f"Missing section `{spec['heading']}`: {spec['means']}")
        elif key == "authorization" and not authorization_has_content(body, spec["heading"]):
            failures.append(
                "Section `## Merge authorization` needs visible maintainer and delegation "
                "scope evidence, not an empty heading or template placeholder."
            )

    return failures


def main():
    manifest = load_manifest()
    for key in ("risk_zones", "evidence", "sections"):
        if key not in manifest:
            die(f"{MANIFEST_PATH} has no `{key}` — refusing to gate against half a manifest.")

    body = os.environ.get("BODY") or ""
    files = changed_files()

    per_file = {f: file_zone(f, manifest["risk_zones"]) for f in files}
    computed = max(per_file.values(), key=SEVERITY.index)

    if computed not in manifest["evidence"]:
        die(f"{MANIFEST_PATH} declares no evidence requirements for zone `{computed}`.")

    lines = ["# AGM review packet", "", "| File | Zone |", "|---|---|"]
    for f, z in sorted(per_file.items()):
        lines.append(f"| `{f}` | {z} |")
    lines += ["", f"**Computed zone: {computed}**", ""]

    if computed == "low":
        failures = []
        lines.append("Zone low: no evidence package required.")
    else:
        failures = evidence_failures(manifest, body, computed)

    # Runs for every zone: redaction is not proportional to risk.
    leaks = scan_for_leaks(body)

    lines.append("")
    if failures:
        lines += ["## Missing evidence", ""]
        lines += [f"- {f}" for f in failures]
        lines.append("")
    if leaks:
        lines += [
            "## Unredacted identifiers in the pull-request body",
            "",
            "The matched values are named by kind and location only — repeating "
            "them here would publish them again.",
            "",
        ]
        for kind, lineno, section in leaks:
            lines.append(
                f"- {kind} at body line {lineno}, under `{section}`. {REMEDY[kind]}"
            )
        lines.append("")
    if not failures and not leaks:
        lines.append(
            "All mechanical evidence gates pass. This does not authenticate "
            "authorization or certify human review. GitHub merge permissions "
            "and configured review requirements still apply."
        )

    report = "\n".join(lines) + "\n"
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)

    sys.exit(1 if (failures or leaks) else 0)


if __name__ == "__main__":
    main()
