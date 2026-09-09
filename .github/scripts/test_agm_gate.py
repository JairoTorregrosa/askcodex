#!/usr/bin/env python3
"""Tests for `agm_gate.py`, the governance gate.

Run them:

    python3 -m unittest discover --start-directory .github/scripts
    python3 .github/scripts/test_agm_gate.py

Standard library only, on purpose. `ci.yml` runs this suite with the python3
that ships on the runner and installs nothing: a gate whose tests need `pip`
would be a gate whose tests need a supply chain.

The suite works two ways, because the gate has two contracts. Most tests
import `agm_gate` and call its functions directly. The rest run it as a
subprocess with a constructed environment, because the EXIT CODE is the part
CI reads — 2 for a gate that could not run, 1 for a gate that failed, 0 for a
pass — and only a real process proves it.

Every gate rule is checked against the real `agm.json`, never a fixture: the
manifest is the contract, and a test that carried its own copy would keep
passing after the two drifted apart.

The identifiers below are FABRICATED. No token, account id, user id, or email
address in this file belongs to anybody. The email-shaped fixtures exist
because catching a real address is the whole point of the redaction scan, and
that direction cannot be tested without something address-shaped.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import agm_gate  # noqa: E402  (needs the sys.path line above)

GATE = Path(agm_gate.__file__).resolve()
MANIFEST = agm_gate.load_manifest()

# --- fabricated fixtures ---------------------------------------------------
# Shapes only. Nothing here is, or resembles, a real credential.
FAKE_EMAIL = "qa.person42@fabricated-widgets-corp.com"
FAKE_ACCT = "acct_00fabricated11deadbeef"
FAKE_USER = "user_77fabricated22cafe"
FAKE_JWT = "eyJmYWJyaWNhdGVkMDAwMEhFQUQ.ZmFicmljYXRlZFBBWUxPQUQ.ZmFicmljYXRlZFNJRw"

# The idioms from the false-positive defect, verbatim. Each is a version pin
# or a pinned action ref, and none is an email address.
VERSION_PINS = [
    "actions/checkout@v4.2.2",
    "Swatinem/rust-cache@v2.7.8",
    "cargo install askcodex@0.1.0",
    "typescript@5.4.2",
    "ubuntu@22.04",
]

# Phrases that ship in .github/PULL_REQUEST_TEMPLATE.md, so they appear in
# nearly every real pull-request body. Copied as literals rather than read
# from the file: this suite is about the gate, and it must fail for the
# gate's reasons only.
TEMPLATE_PHRASES = [
    "Redact every transcript you paste: no token values, no account_id, no",
    "user_id, no email. Use acct_REDACTED / user_REDACTED / email_REDACTED.",
    "Risk zone: <!-- low | medium | high | critical -->",
]


def body_for(zone, *, omit=(), declared=None, extra=""):
    """A pull-request body that satisfies `zone`, built from the manifest.

    `omit` drops sections by key; `declared` overrides the declared zone;
    """
    parts = [f"Risk zone: {zone if declared is None else declared}", ""]
    for key in MANIFEST["evidence"][zone]:
        if key in omit:
            continue
        spec = MANIFEST["sections"][key]
        evidence = ("Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge this change"
                    if key == "authorization" else f"Fabricated evidence for {key}.")
        parts += [spec["heading"], "", evidence, ""]
    if extra:
        parts += [extra, ""]
    return "\n".join(parts)


def run_gate(*, body=None, changed_files=None, changed_files_file=None, summary=None,
             script=None):
    """Run the gate as a process and return the CompletedProcess.

    The child environment is scrubbed of every variable the gate reads before
    anything is set. Inheriting them would make the result depend on the
    machine — and on a CI runner GITHUB_STEP_SUMMARY is set, so an inherited
    one would append these fabricated leak reports to the real job summary.
    """
    env = os.environ.copy()
    for key in ("BODY", "CHANGED_FILES", "CHANGED_FILES_FILE", "GITHUB_STEP_SUMMARY"):
        env.pop(key, None)
    if body is not None:
        env["BODY"] = body
    if changed_files is not None:
        env["CHANGED_FILES"] = changed_files
    if changed_files_file is not None:
        env["CHANGED_FILES_FILE"] = changed_files_file
    if summary is not None:
        env["GITHUB_STEP_SUMMARY"] = summary
    return subprocess.run(
        [sys.executable, str(script or GATE)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


class ZoneComputationTests(unittest.TestCase):
    """agm.json's zone_rule: highest-severity zone whose pattern matches."""

    def zone(self, path):
        return agm_gate.file_zone(path, MANIFEST["risk_zones"])

    def test_critical_paths(self):
        for path in ("install.sh", "agm.json", "GOVERNANCE.md", "skill/SKILL.md"):
            with self.subTest(path=path):
                self.assertEqual(self.zone(path), "critical")

    def test_dot_github_is_critical_at_any_depth(self):
        # `*` matches `/` here, which is what makes `.github/*` cover the
        # workflows and this very script.
        for path in (".github/workflows/ci.yml", ".github/scripts/agm_gate.py",
                     ".github/scripts/test_agm_gate.py"):
            with self.subTest(path=path):
                self.assertEqual(self.zone(path), "critical")

    def test_high_paths(self):
        for path in ("src/main.rs", "src/http.rs", "src/endpoints/images.rs",
                     "Cargo.lock"):
            with self.subTest(path=path):
                self.assertEqual(self.zone(path), "high")

    def test_medium_is_the_rest_of_src(self):
        self.assertEqual(self.zone("src/render.rs"), "medium")

    def test_low_is_everything_else(self):
        for path in ("README.md", "docs/PROTOCOL.md", "assets/demo.svg"):
            with self.subTest(path=path):
                self.assertEqual(self.zone(path), "low")

    def test_a_file_matching_several_zones_takes_the_highest(self):
        # src/auth.rs matches critical (`src/auth.rs`), medium (`src/*`) and
        # low (`*`). Every file matches at least two, because `*` is the low
        # zone's pattern.
        self.assertEqual(self.zone("src/auth.rs"), "critical")
        self.assertEqual(self.zone("src/auth/store.rs"), "critical")
        self.assertEqual(self.zone("src/auth/session.rs"), "critical")
        self.assertEqual(self.zone("src/auth/lock.rs"), "critical")
        self.assertEqual(self.zone("src/http/target.rs"), "high")
        # src/main.rs matches high, medium and low.
        self.assertEqual(self.zone("src/main.rs"), "high")

    def test_the_order_zones_appear_in_does_not_decide(self):
        # agm.json happens to list its zones from critical down, so there
        # "first match" and "highest match" agree and a first-match bug would
        # hide. The rule is the highest; prove it on the same zones reversed.
        upside_down = list(reversed(MANIFEST["risk_zones"]))
        for path, expected in (("src/auth.rs", "critical"),
                               (".github/workflows/ci.yml", "critical"),
                               ("src/main.rs", "high"),
                               ("src/render.rs", "medium"),
                               ("README.md", "low")):
            with self.subTest(path=path):
                self.assertEqual(agm_gate.file_zone(path, upside_down), expected)

    def test_severity_order_is_ascending(self):
        self.assertEqual(agm_gate.SEVERITY, ["low", "medium", "high", "critical"])

    def test_change_zone_is_the_highest_across_files(self):
        result = run_gate(
            body=body_for("high"),
            changed_files="README.md\nsrc/render.rs\nsrc/main.rs\n",
        )
        self.assertIn("**Computed zone: high**", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class RequiredSectionTests(unittest.TestCase):
    """agm.json's evidence table, one zone at a time."""

    def failures(self, body, zone):
        return agm_gate.evidence_failures(MANIFEST, body, zone)

    def test_a_complete_body_passes_in_every_zone(self):
        for zone in ("medium", "high", "critical"):
            with self.subTest(zone=zone):
                self.assertEqual(self.failures(body_for(zone), zone), [])

    def test_each_required_section_is_actually_required(self):
        for zone in ("medium", "high", "critical"):
            for key in MANIFEST["evidence"][zone]:
                with self.subTest(zone=zone, section=key):
                    failures = self.failures(body_for(zone, omit=(key,)), zone)
                    self.assertEqual(len(failures), 1, failures)
                    needle = MANIFEST["sections"][key]["heading"]
                    self.assertIn(needle.lower(), failures[0].lower())

    def test_a_lower_zones_package_does_not_satisfy_a_higher_one(self):
        # The classic near-miss: a medium package on a critical change.
        failures = self.failures(body_for("medium", declared="critical"), "critical")
        self.assertTrue(failures)
        for key in ("assumptions", "risk", "second_review"):
            heading = MANIFEST["sections"][key]["heading"]
            self.assertTrue(any(heading in f for f in failures), (key, failures))

    def test_undeclared_zone_fails(self):
        body = body_for("medium").replace("Risk zone: medium", "")
        failures = self.failures(body, "medium")
        self.assertTrue(any("Declare the risk zone" in f for f in failures), failures)

    def test_declared_zone_must_match_the_computed_one(self):
        failures = self.failures(body_for("critical", declared="low"), "critical")
        self.assertTrue(any("does not match" in f for f in failures), failures)

    def test_declared_zone_is_case_insensitive(self):
        self.assertEqual(self.failures(body_for("high", declared="HIGH"), "high"), [])


class MergeAuthorizationTests(unittest.TestCase):
    """Evidence checks never impersonate human review or authenticate prose."""

    def test_critical_evidence_needs_no_human_identity_claim(self):
        body = body_for("critical")
        self.assertNotIn("I am a human", body)
        self.assertNotIn("[x]", body)
        self.assertEqual(
            agm_gate.evidence_failures(MANIFEST, body, "critical"), []
        )

    def test_human_checkbox_cannot_replace_authorization_evidence(self):
        body = body_for(
            "critical", omit=("authorization",),
            extra="- [x] I am a human. I approve this change."
        )
        failures = agm_gate.evidence_failures(MANIFEST, body, "critical")
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("## Merge authorization", failures[0])

    def test_critical_keeps_independent_review_and_authorization_evidence(self):
        self.assertIn("second_review", MANIFEST["evidence"]["critical"])
        self.assertIn("authorization", MANIFEST["evidence"]["critical"])
        self.assertNotIn("confirmation", MANIFEST["sections"])

    def test_template_and_manifest_use_the_same_evidence_headings(self):
        template = (GATE.parents[2] / ".github/PULL_REQUEST_TEMPLATE.md").read_text()
        for key in MANIFEST["evidence"]["critical"]:
            self.assertIn(MANIFEST["sections"][key]["heading"], template)
        self.assertNotIn("I am a human", template)

    def test_summary_does_not_claim_review_or_authorization(self):
        result = run_gate(body=body_for("critical"), changed_files="src/auth.rs")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("does not authenticate authorization or certify human review", result.stdout)


class AuthorizationContentTests(unittest.TestCase):
    def failures_for(self, content):
        return agm_gate.evidence_failures(
            MANIFEST, body_for("critical", omit=("authorization",),
                               extra="## Merge authorization\n\n" + content), "critical")

    def test_empty_whitespace_and_comment_templates_fail(self):
        for content in ["", " \n\t", "<!-- Name maintainer and scope -->",
                        "<!-- unfinished template"]:
            with self.subTest(content=content):
                self.assertEqual(len(self.failures_for(content)), 1)

    def test_placeholder_only_content_fails(self):
        for content in ["TODO", "TBD", "- [ ]", "<maintainer> <scope>",
                        "TODO: name the maintainer and describe scope",
                        "Maintainer: TODO\nScope: TBD", "### Maintainer and scope"]:
            with self.subTest(content=content):
                self.assertEqual(len(self.failures_for(content)), 1)

    def test_prose_in_another_section_cannot_fill_empty_authorization(self):
        for heading in ["## Notes", "# Another section"]:
            self.assertEqual(len(self.failures_for(
                heading + "\nJairo authorized implementation and merge.")), 1)

    def test_authorization_in_comment_or_code_is_not_visible_evidence(self):
        for content in [
            "<!-- Jairo authorized implementation and merge. -->",
            "```text\nJairo authorized implementation and merge.\n```",
            "~~~text\nJairo authorized implementation and merge.\n~~~",
        ]:
            self.assertEqual(len(self.failures_for(content)), 1)

    def test_heading_only_embedded_in_prose_is_not_an_authorization_section(self):
        body = body_for("critical", omit=("authorization",),
                        extra="See ## Merge authorization for maintainer delivery scope.")
        self.assertEqual(len(agm_gate.evidence_failures(MANIFEST, body, "critical")), 1)

    def test_prose_alone_is_not_a_structured_grant(self):
        self.assertEqual(self.failures_for(
            "<!-- template guidance -->\nJairo authorized implementation and merge. "
            "No human code review is claimed."), self.failures_for("denied"))

    def test_subsections_can_hold_real_authorization_prose(self):
        self.assertEqual(self.failures_for(
            "### Delivery\nAuthorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"), [])


    def test_explicit_grant_and_scoped_maintainer_are_required(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        self.assertEqual(self.failures_for(valid), [])
        for content in ["No authorization was received.", "- [x] I am a human.",
                        valid.replace("granted", "denied"), valid.replace("granted", "pending"),
                        valid.replace("Maintainer: @fixture-maintainer\n", ""),
                        valid.replace("Scope: implement and merge", ""),
                        valid.replace("Authorization: granted\n", "")]:
            with self.subTest(content=content):
                self.assertEqual(len(self.failures_for(content)), 1)

    def test_invalid_login_and_scope_placeholders_are_rejected(self):
        for login in ["", "@<login>", "@-name", "@name-", "@two--hyphens", "@with_underscore", "@a" * 40]:
            self.assertEqual(len(self.failures_for(
                f"Authorization: granted\nMaintainer: {login}\nScope: implement and merge")), 1)
        for scope in ["", "---", "123", "TODO", "TBD", "<delegated scope>", "[scope]", "describe the scope", "pending approval"]:
            self.assertEqual(len(self.failures_for(
                f"Authorization: granted\nMaintainer: @fixture-maintainer\nScope: {scope}")), 1)

    def test_duplicate_and_conflicting_required_fields_are_rejected(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        for duplicate in ["Authorization: granted", "Authorization: denied",
                          "Maintainer: @another-maintainer", "Scope: no merge"]:
            self.assertEqual(len(self.failures_for(valid + "\n" + duplicate)), 1)

    def test_repeated_authorization_sections_are_rejected(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        for between in ["", "## Notes\nUnrelated review context.\n"]:
            for repeated in [valid, "Authorization: denied"]:
                self.assertEqual(len(self.failures_for(
                    valid + "\n" + between + "## Merge authorization\n" + repeated)), 1)

    def test_structured_fields_cannot_come_from_comments_fences_or_other_sections(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        for content in ["<!--\n" + valid + "\n-->", "```\n" + valid + "\n```",
                        "## Notes\n" + valid]:
            self.assertEqual(len(self.failures_for(content)), 1)

    def test_indented_code_cannot_supply_fields_or_fence_markers(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        for indent in ["    ", "\t", " \t", "  \t"]:
            example = "\n".join(indent + line for line in valid.splitlines())
            self.assertEqual(len(self.failures_for(example)), 1)
            self.assertEqual(self.failures_for(indent + "```\n" + valid), [])
            self.assertEqual(self.failures_for(indent + "<!-- literal example\n\n" + valid), [])

    def test_only_bare_matching_rails_close_authorization_examples(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        for rail in ["```", "~~~", "````"]:
            for fake_close in [rail + "json", rail + " <!-- literal -->", rail[0] * 2]:
                self.assertEqual(len(self.failures_for(
                    rail + "text\n" + fake_close + "\n" + valid + "\n" + rail)), 1)
            self.assertEqual(self.failures_for(rail + "text\nexample\n" + rail + "  \n" + valid), [])

    def test_comment_syntax_inside_code_is_literal(self):
        valid = "Authorization: granted\nMaintainer: @fixture-maintainer\nScope: implement and merge"
        self.assertEqual(self.failures_for("```text\n<!-- example\n```\n" + valid), [])
        self.assertEqual(self.failures_for("<!--\n```\n-->\n" + valid), [])

class RedactionCatchTests(unittest.TestCase):
    """The scan must catch a real leak — in any zone, inside a fence or not."""

    def kinds(self, text):
        return {kind for kind, _lineno, _section in agm_gate.scan_for_leaks(text)}

    def test_catches_an_email_address(self):
        self.assertEqual(self.kinds(f"Contact {FAKE_EMAIL} about it."),
                         {agm_gate.KIND_EMAIL})

    def test_catches_account_and_user_identifiers(self):
        self.assertEqual(self.kinds(f'"account_id": "{FAKE_ACCT}"'),
                         {agm_gate.KIND_ID})
        self.assertEqual(self.kinds(f'"user_id": "{FAKE_USER}"'),
                         {agm_gate.KIND_ID})

    def test_catches_a_token(self):
        self.assertEqual(self.kinds(f"Authorization: Bearer {FAKE_JWT}"),
                         {agm_gate.KIND_JWT})

    def test_catches_a_token_that_lost_its_signature(self):
        head = FAKE_JWT.split(".")[0]
        self.assertEqual(self.kinds(f"access_token={head}"), {agm_gate.KIND_JWT})

    def test_reports_the_line_number_and_the_enclosing_heading(self):
        body = "\n".join([
            "## Behavior evidence",           # 1
            "",                               # 2
            "Ran the command:",               # 3
            f"  account: {FAKE_ACCT}",        # 4
        ])
        leaks = agm_gate.scan_for_leaks(body)
        self.assertEqual(leaks, [(agm_gate.KIND_ID, 4, "## Behavior evidence")])

    def test_never_names_the_value(self):
        # The report is written to a public job summary. Naming the match
        # would leak it a second time, to a wider audience.
        for secret in (FAKE_EMAIL, FAKE_ACCT, FAKE_USER, FAKE_JWT):
            with self.subTest(secret=secret[:6] + "..."):
                leaks = agm_gate.scan_for_leaks(f"## Evidence\n\nvalue: {secret}\n")
                self.assertTrue(leaks)
                self.assertNotIn(secret, repr(leaks))

    def test_a_leaking_heading_is_not_quoted_back(self):
        body = f"## Transcript for {FAKE_ACCT}\n\nnothing else\n"
        leaks = agm_gate.scan_for_leaks(body)
        self.assertTrue(leaks)
        for _kind, _lineno, section in leaks:
            self.assertNotIn(FAKE_ACCT, section)
            self.assertIn("needs redaction", section)

    def test_a_leak_inside_a_code_fence_is_still_caught(self):
        # Fences are where pasted transcripts live. A leak there is a leak.
        body = "\n".join([
            "## Behavior evidence",            # 1
            "",                                # 2
            "```console",                      # 3
            "$ askcodex auth status",              # 4
            f"account: {FAKE_ACCT}",           # 5
            "```",                             # 6
        ])
        self.assertEqual(
            agm_gate.scan_for_leaks(body),
            [(agm_gate.KIND_ID, 5, "## Behavior evidence")],
        )

    def test_an_unredacted_address_beats_a_reserved_lookalike(self):
        # `evilnoreply.github.com` is not `noreply.github.com`: the reserved
        # rule is about a DNS label boundary, not a string suffix.
        self.assertEqual(self.kinds("mail person@evilnoreply.github.com now"),
                         {agm_gate.KIND_EMAIL})

    def test_reserved_names_are_not_leaks(self):
        for address in (
            "someone@example.com",
            "someone@example.org",
            "nobody@host.invalid",
            "dev@my-box.localhost",
            "noreply@github.com",
            "no-reply@fabricated-widgets-corp.com",
            "123456+contributor@users.noreply.github.com",
        ):
            with self.subTest(address=address):
                self.assertEqual(self.kinds(f"from {address} here"), set())

    def test_the_scan_runs_in_zone_low(self):
        # A leaked credential is not a documentation change.
        result = run_gate(
            body=f"Typo fix.\n\nToken: {FAKE_JWT}\n",
            changed_files="README.md\n",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(agm_gate.KIND_JWT, result.stdout)
        self.assertNotIn(FAKE_JWT, result.stdout)


class RedactionPrecisionTests(unittest.TestCase):
    """...and must not fire on the idioms a real pull-request body carries."""

    def kinds(self, text):
        return {kind for kind, _lineno, _section in agm_gate.scan_for_leaks(text)}

    def test_a_version_pin_is_not_an_email_address(self):
        for pin in VERSION_PINS:
            with self.subTest(pin=pin):
                self.assertEqual(self.kinds(f"Bumped {pin} in this change."), set())

    def test_a_sha_pinned_action_ref_is_not_a_leak(self):
        line = ("uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
                " # v4.4.0")
        self.assertEqual(self.kinds(line), set())

    def test_more_version_shapes(self):
        for pin in ("python@3.12", "node@22.x", "askcodex@1.0.0-beta.1",
                    "dotnet@4.2.2.0", "postgres@16.2"):
            with self.subTest(pin=pin):
                self.assertEqual(self.kinds(pin), set())

    def test_a_real_tld_still_reads_as_an_address(self):
        # The version-pin exemption keys on the last label, so prove the
        # exemption did not swallow the addresses it sits next to.
        for address in (FAKE_EMAIL,
                        "qa.person42@fabricated-widgets-corp.dev",
                        "qa.person42@mail.fabricated-widgets-corp.museum",
                        "qa.person42@fabricated-widgets-corp.co.uk"):
            with self.subTest(address=address):
                self.assertEqual(self.kinds(address), {agm_gate.KIND_EMAIL})

    def test_the_pull_request_template_does_not_trip_the_scan(self):
        # These phrases ship in the template, so a gate that fired on them
        # would fail nearly every pull request and be routed around.
        for phrase in TEMPLATE_PHRASES:
            with self.subTest(phrase=phrase[:32]):
                self.assertEqual(self.kinds(phrase), set())

    def test_prose_about_identifiers_is_not_an_identifier(self):
        for phrase in ("the user_id field", "an account_id like acct_REDACTED",
                       "user_REDACTED and email_REDACTED", "user_name", "acct_id"):
            with self.subTest(phrase=phrase):
                self.assertEqual(self.kinds(phrase), set())

    def test_a_complete_evidence_package_passes_the_scan(self):
        self.assertEqual(self.kinds(body_for("critical")), set())


class HeadingAttributionTests(unittest.TestCase):
    """Fences hide headings from the attribution, and nothing else."""

    def sections(self, body):
        return [section for _kind, _lineno, section in agm_gate.scan_for_leaks(body)]

    def test_a_comment_inside_a_fence_is_not_a_heading(self):
        body = "\n".join([
            "## Behavior evidence",       # 1
            "",                           # 2
            "```sh",                      # 3
            "# install and run",          # 4  <- a shell comment, not a heading
            "./install.sh",               # 5
            f"# account {FAKE_ACCT}",     # 6
            "```",                        # 7
        ])
        self.assertEqual(self.sections(body), ["## Behavior evidence"])

    def test_attribution_resumes_after_the_fence_closes(self):
        body = "\n".join([
            "## Checks",                  # 1
            "```",                        # 2
            "# not a heading",            # 3
            "```",                        # 4
            "## Risk",                    # 5
            f"leaked {FAKE_ACCT}",        # 6
        ])
        self.assertEqual(self.sections(body), ["## Risk"])

    def test_tilde_fences_count_too(self):
        body = "\n".join([
            "## Risk",                    # 1
            "~~~",                        # 2
            "# not a heading",            # 3
            f"{FAKE_ACCT}",               # 4
            "~~~",                        # 5
        ])
        self.assertEqual(self.sections(body), ["## Risk"])

    def test_a_shorter_rail_does_not_close_a_longer_fence(self):
        body = "\n".join([
            "## Risk",                    # 1
            "````",                       # 2  four backticks
            "```",                        # 3  three: content, not a closer
            "# not a heading",            # 4
            "````",                       # 5  closes
            f"{FAKE_ACCT}",               # 6
        ])
        self.assertEqual(self.sections(body), ["## Risk"])

    def test_a_backtick_rail_does_not_close_a_tilde_fence(self):
        body = "\n".join([
            "## Risk",                    # 1
            "~~~",                        # 2
            "```",                        # 3
            "# not a heading",            # 4
            "~~~",                        # 5
            f"{FAKE_ACCT}",               # 6
        ])
        self.assertEqual(self.sections(body), ["## Risk"])

    def test_an_info_string_does_not_close_the_fence(self):
        body = "\n".join([
            "## Risk",                    # 1
            "```console",                 # 2
            "```json",                    # 3  still inside: not a bare rail
            "# not a heading",            # 4
            "```",                        # 5
            f"{FAKE_ACCT}",               # 6
        ])
        self.assertEqual(self.sections(body), ["## Risk"])

    def test_real_headings_outside_fences_still_attribute(self):
        body = "\n".join([
            "intro",                      # 1
            f"{FAKE_ACCT}",               # 2  before any heading
            "## Summary",                 # 3
            f"{FAKE_USER}",               # 4
        ])
        self.assertEqual(
            self.sections(body), ["(before the first heading)", "## Summary"]
        )


class ChangedFileListTests(unittest.TestCase):
    """A gate that cannot see the change refuses to run. Exit 2, never 0.

    This is the masking default the gate exists to not have: an absent list
    computes zone `low`, requires no evidence, and passes everything.
    """

    def assert_refused(self, result, *, needle=None):
        self.assertEqual(result.returncode, 2,
                         f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertIn("agm_gate:", result.stderr)
        self.assertNotIn("All mechanical gates pass", result.stdout)
        if needle:
            self.assertIn(needle, result.stderr)

    def test_no_list_at_all_is_refused(self):
        self.assert_refused(run_gate(body=body_for("critical")),
                            needle="no changed-file list")

    def test_an_empty_inline_list_is_refused(self):
        self.assert_refused(run_gate(body=body_for("critical"), changed_files=""),
                            needle="empty")

    def test_a_whitespace_only_inline_list_is_refused(self):
        self.assert_refused(
            run_gate(body=body_for("critical"), changed_files="\n  \n\t\n"),
            needle="empty",
        )

    def test_an_empty_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed"
            path.write_text("", encoding="utf-8")
            self.assert_refused(
                run_gate(body=body_for("critical"), changed_files_file=str(path)),
                needle="empty",
            )

    def test_a_file_of_nul_separators_only_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed"
            path.write_text("\0\0", encoding="utf-8")
            self.assert_refused(
                run_gate(body=body_for("critical"), changed_files_file=str(path)),
                needle="empty",
            )

    def test_an_empty_CHANGED_FILES_FILE_value_is_refused(self):
        # An unresolved workflow expression exports the variable as "". That
        # must not read as "unset".
        self.assert_refused(
            run_gate(body=body_for("critical"), changed_files_file=""),
            needle="CHANGED_FILES_FILE is set but empty",
        )

    def test_an_empty_CHANGED_FILES_FILE_does_not_let_the_inline_list_win(self):
        self.assert_refused(
            run_gate(body=body_for("critical"), changed_files_file="",
                     changed_files="README.md"),
        )

    def test_an_unreadable_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "does-not-exist")
            self.assert_refused(
                run_gate(body=body_for("critical"), changed_files_file=missing),
                needle="cannot read CHANGED_FILES_FILE",
            )

    def test_both_sources_at_once_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed"
            path.write_text("install.sh\0", encoding="utf-8")
            self.assert_refused(
                run_gate(body=body_for("critical"), changed_files="README.md",
                         changed_files_file=str(path)),
                needle="both set",
            )

    def test_a_nul_separated_file_is_read_as_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed"
            # git diff -z: NUL-separated, trailing NUL, paths never quoted.
            path.write_text("README.md\0src/main.rs\0", encoding="utf-8")
            result = run_gate(body=body_for("high"), changed_files_file=str(path))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("**Computed zone: high**", result.stdout)

    def test_a_path_containing_a_newline_stays_one_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed"
            path.write_text("docs/od\nd name.md\0", encoding="utf-8")
            result = run_gate(body="", changed_files_file=str(path))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("| `docs/od\nd name.md` | low |", result.stdout)


class ManifestTests(unittest.TestCase):
    """No manifest, half a manifest: refuse. Never gate against a guess."""

    def gate_in_a_tree_with(self, tmp, manifest_text):
        """Copy the gate into <tmp>/.github/scripts and write <tmp>/agm.json."""
        scripts = Path(tmp) / ".github" / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(GATE, scripts / GATE.name)
        if manifest_text is not None:
            (Path(tmp) / "agm.json").write_text(manifest_text, encoding="utf-8")
        return scripts / GATE.name

    def test_a_missing_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self.gate_in_a_tree_with(tmp, None)
            result = run_gate(body="", changed_files="README.md", script=script)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("cannot read the manifest", result.stderr)

    def test_an_unparseable_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self.gate_in_a_tree_with(tmp, "{not json")
            result = run_gate(body="", changed_files="README.md", script=script)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("not valid JSON", result.stderr)

    def test_half_a_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self.gate_in_a_tree_with(tmp, '{"risk_zones": [], "evidence": {}}')
            result = run_gate(body="", changed_files="README.md", script=script)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("half a manifest", result.stderr)

    def test_a_zone_with_no_evidence_rule_is_refused(self):
        manifest = (
            '{"risk_zones": [{"level": "low", "paths": ["*"]}],'
            ' "evidence": {"critical": []}, "sections": {}}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            script = self.gate_in_a_tree_with(tmp, manifest)
            result = run_gate(body="", changed_files="README.md", script=script)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("no evidence requirements for zone", result.stderr)


class ExitCodeTests(unittest.TestCase):
    """0 pass, 1 gate failure, 2 could not run. CI reads nothing else."""

    def test_zero_when_every_gate_passes(self):
        result = run_gate(body=body_for("critical"), changed_files="install.sh\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All mechanical evidence gates pass", result.stdout)

    def test_zone_low_needs_no_evidence_package(self):
        result = run_gate(body="", changed_files="README.md\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Zone low: no evidence package required.", result.stdout)

    def test_one_when_evidence_is_missing(self):
        result = run_gate(body="Risk zone: critical\n", changed_files="install.sh\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("## Missing evidence", result.stdout)

    def test_one_when_the_declared_zone_is_wrong(self):
        result = run_gate(body=body_for("critical", declared="low"),
                          changed_files="install.sh\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("does not match computed zone `critical`", result.stdout)

    def test_one_when_the_body_leaks(self):
        body = body_for("critical", extra=f"Ran it as {FAKE_EMAIL}.")
        result = run_gate(body=body, changed_files="install.sh\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Unredacted identifiers", result.stdout)
        self.assertIn(agm_gate.KIND_EMAIL, result.stdout)
        self.assertNotIn(FAKE_EMAIL, result.stdout)
        self.assertNotIn(FAKE_EMAIL, result.stderr)

    def test_the_remedy_for_a_token_says_rotate_not_edit(self):
        result = run_gate(body=body_for("critical", extra=f"token {FAKE_JWT}"),
                          changed_files="install.sh\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("rotate it at the issuer", result.stdout)
        self.assertNotIn(FAKE_JWT, result.stdout)

    def test_the_report_goes_to_the_job_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            summary.write_text("", encoding="utf-8")
            result = run_gate(body=body_for("critical"),
                              changed_files="install.sh\n",
                              summary=str(summary))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            written = summary.read_text(encoding="utf-8")
            self.assertIn("# AGM review packet", written)
            self.assertIn("**Computed zone: critical**", written)

    def test_the_summary_never_carries_the_value_either(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            result = run_gate(body=body_for("critical", extra=f"acct {FAKE_ACCT}"),
                              changed_files="install.sh\n",
                              summary=str(summary))
            self.assertEqual(result.returncode, 1, result.stdout)
            written = summary.read_text(encoding="utf-8")
            self.assertIn(agm_gate.KIND_ID, written)
            self.assertNotIn(FAKE_ACCT, written)

    def test_a_body_is_data_never_a_command(self):
        # The body reaches the gate through the environment. If it were ever
        # interpolated into a shell line, this would run `id` and leave the
        # marker behind. It is quoted back into the report unchanged instead.
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "the-body-was-executed"
            result = run_gate(
                body=body_for("critical", extra=f"$(id > {marker})"),
                changed_files="install.sh\n",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
