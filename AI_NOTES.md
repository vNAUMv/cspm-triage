# AI-assisted development log

Working log of building this project with an AI coding agent (Claude Code in PyCharm),
with a second AI (chat assistant) used for planning, review and AWS guidance.
One entry per notable moment. Source material for the "How this was built" section of the README.

## Template

- **Stage:**
- **Task given to the agent:**
- **What worked:**
- **What went wrong:**
- **How it was caught:**
- **What I changed:** (prompt, CLAUDE.md rule, task size, approval mode)

## Key numbers

| Scan | FAIL findings | Need attention after triage | What changed before this scan |
|---|---|---|---|
| 1 | 58 | 14 (43 accepted) | baseline |
| 2 | — | 3 | password policy, GuardDuty, Access Analyzer, audit user moved to a group; 7 new findings caused by the fixes themselves, reviewed and accepted |
| 3 | 64 | 6 | multi-region CloudTrail created, unused role deleted; 17 new findings about the log bucket and KMS key, 11 accepted |
| 4 | — | **0** | 6 fixes on the log bucket and KMS key |

The raw FAIL count barely moved (58 → 64) while actionable findings went from 14 to 0.
Raw FAIL count is a poor metric; triage and diff are what make it meaningful.

## Entries

### Setup: approval mode

- **What happened:** Claude Code started in auto mode.
- **What I changed:** Switched to manual approval for every command and file edit. Giving an agent
  unattended write and shell access to a repo that will contain security tooling is not acceptable.
  Push to GitHub stays manual too (see stage 1).

### Stage 0: scaffold

- **What went wrong:** ruff failed on 9 files with no trailing newline (the agent's write tool dropped it).
- **How it was caught:** ruff in the agent's own check run.
- **What I changed:** Nothing beyond `ruff check --fix`; no other changes were made by the fix.

### Stage 1: Finding model, OCSF parser, sanitized fixture

- **What worked:**
  - The agent did not invent an Informational finding for the fixture: there was none in the real
    scan, so it asked instead. A direct effect of the CLAUDE.md rule "don't invent fields of the
    Prowler OCSF format".
  - It deviated from the approved plan once (where `region` is read from), said so explicitly and
    explained why, instead of changing it silently.
  - It validated that decision against all 92 findings of the first real scan rather than assuming.
  - It promised to show the fixture before committing, and did.
- **Data handling:**
  - Two layers against leaks: the sanitizer refuses to write if any original identifier remains, and
    a repo test checks that every 12-digit number in the fixture is a known fake account ID. The test
    works without knowing the real ID, so the test itself discloses nothing.
  - The first, one-off sanitizer had real values hardcoded and was kept out of git. It was later
    rewritten as a generic `scripts/sanitize_fixture.py` that reads real values only from its input
    and has its own tests on fake data.
  - The agent did not repeat a grep that contained the real account ID after I stopped it, and
    understood why: the real ID should not appear in its commands or context.
- **What went wrong:** `git push` failed: the SSH key has a passphrase and the agent's shell has no
  TTY to prompt. The agent diagnosed it correctly, but its suggested workaround (running `ssh-add`
  from its own shell) could not work for the same reason.
- **What I changed:** I push manually. This doubles as a human review gate before anything is public.

### Stage 1b: generic sanitizer

- **What worked:**
  - bandit flagged the string `"0.0.0.0"` (B104, bind to all interfaces) — a false positive, the
    script only keeps that value as data. The agent removed the literal instead of adding `# nosec`.
    Scanner findings are fixed or explained, not silenced.
  - It re-checked the fixture for leaks and ran pytest, ruff and bandit before reporting.
  - It applied a CLAUDE.md rule to its own new code without being prompted.

### Stage 2a: triage and accepted risks

- **What went wrong:** The agent applied the "don't invent fields" rule too literally: it treated
  `Informational` as an unknown severity because it did not appear in the sample.
- **How it was caught:** Plan review; verified against the tool itself
  (`prowler aws --help` lists `critical,high,medium,low,informational`).
- **What I changed:** Told it the value is documented and gave the evidence. Also decided that
  unknown severities sort *above* Critical: OCSF has values above Critical (Fatal), so an unknown
  value may be more severe, not less.
- **Validation:** Ran triage on the real scan and compared with a hand count
  (58 FAIL: 1 Critical, 11 High, 32 Medium, 14 Low). Exact match. The agent's own tests only check
  its own understanding of the task; an external reference checks whether that understanding is right.

### Stage 2a: writing real accepted risks

- **Process:** Every accepted risk has an owner, a reason and an expiry date. Expiry depends on the
  kind of decision (not applicable: 6 months, cost-based: 3 months, temporary: 1 month).
  Exceptions that depend on a compensating control say so (e.g. CloudWatch alarm checks are accepted
  only while CloudTrail and GuardDuty are enabled).
- **What went wrong (twice):** I guessed which resource a finding points to instead of checking.
  - A Critical finding on `AdministratorAccess`: the resource is the AWS-managed policy itself, not
    the group it is attached to. A resource-scoped exception therefore cannot tell *who* has admin.
    I first assumed narrower per-principal checks would catch new attachments; the scan showed checks
    exist for users and groups but not for roles. The exception was kept, with the gap and the
    compensating control written into the reason.
  - `cloudtrail_*` checks about the log bucket point to the trail, not the bucket, so the bucket
    pattern did not match.
- **How it was caught:** The first by checking the finding's resource before writing the exception;
  the second by the diff (two unexpected "new" findings). Both failures were safe: a non-matching
  exception shows the finding instead of hiding it.
- **Lesson:** Always look at a finding's actual resource before writing an exception for it.
- A finding on an AWS service-linked role (`AWSServiceRoleForSupport`) is not actionable — it cannot
  be deleted or edited — so it was accepted, scoped to that exact role ARN, not to the whole check.

### Stage 2b: diff between scans

- **What went wrong:** My fallback idea for matching findings across scans
  (check + region + resource) was wrong.
- **How it was caught:** Comparing two real scans: one check emits one finding per attached policy,
  so two findings shared the same check, region and resource. Only `finding_info.uid` told them apart.
  The same comparison showed the uid is deterministic across scans.
- **What I changed:** Passed the evidence to the agent as facts, not guesses. Match by uid only;
  duplicate uids within a scan are an error.
- **What worked:** The agent found a case I had not considered: some checks report a placeholder
  resource (`detector/unknown`) while a feature is off and the real resource once it is on, so the
  uid changes exactly when something gets fixed. It added "gone" reasons so these are reported as
  "likely fixed" hints, never counted as resolved.
- **Fail-open caught in review:** An empty current scan would have shown every finding as "gone",
  which looks like a huge improvement but usually means the scan failed. Changed to an error.
- **Naming:** A reason first called `NEW_COVERAGE` was renamed to `CHECK_REGION_NOT_IN_BASELINE`.
  A new region appeared because I created resources there, not because scan scope changed.
  Hints should state facts, not interpretations.
- **Process:** The agent had read the real scans on its own initiative (approved commands, but not
  part of the task) and printed a resource ID to the terminal. I added a CLAUDE.md rule: real scans
  are read only when I ask, and only counts and check names are printed. The agent followed this
  rule in every later stage without being reminded, including declining to open a real report.

### Stage 3: CLI and Markdown report

- **Design decisions from review:**
  - Exit codes: 0 = clean, 1 = findings need attention / something new, 2 = usage or input error.
    A broken run must never look like a pass in CI. An empty scan is exit 2 for triage too.
  - The diff gate also fails on a severity increase and on an expired exception; both would
    otherwise pass silently.
  - The source of accepted risks is always printed to stderr, so a run from the wrong directory
    (no exceptions file found) is visible in CI logs.
- **Untrusted data in reports:** Resource names, details and tags can be set by anyone with access
  to the account. Values are escaped, and the agent found that `\|` inside a code span can still
  split a table cell in GFM. It said so and switched to a simpler fallback (escaped plain text for
  values with special characters) instead of a fragile workaround.
- **Readability:** The first report version was hard to read (wide tables, account ID in every row,
  two findings that looked identical). Changed to: account once in the header, short resource names,
  one block per finding needing attention, accepted risks grouped by exception, and a short note
  that tells otherwise identical rows apart.
- **`--redact-account`:** Replaces account IDs with `<account>`, and refuses to write the report if
  any 12-digit number remains. It is documented as removing account IDs only — user, role, trail and
  bucket names are not removed — and is never called anonymization. Sample reports for the README
  are generated from the sanitized fixture, not from real scans.
- **What went wrong:** My own leak check had a false positive: `[0-9]{12}` matched inside a
  14-digit timestamp in the scan file name.
- **Lesson:** Check for the exact secret value to verify a known secret is gone; use patterns to
  find unknown ones.
- **Validation on real data:** triage exit 0 (0 need attention, 58 accepted); diff scan 2 → 3
  exit 1 (6 new); diff scan 1 → 4 exit 0.

### CI (GitHub Actions)

Jira integration was postponed, so CI came before it.

- **Design:** four jobs (lint, test, security, smoke), `permissions: contents: read`, no secrets,
  `persist-credentials: false` on checkout. Third-party actions are pinned by full commit SHA and
  updated by Dependabot. The test job runs a matrix of the declared minimum Python (3.11) and the
  newest (3.14): testing the declared minimum matters more than avoiding a duplicated version number.
- **gitleaks:** run as the MIT-licensed CLI rather than the official action, so no license key or
  secrets are needed. The release tarball is verified with `sha256sum -c` before it runs, it scans
  the full history (`fetch-depth: 0`), and `--redact` keeps any match out of the public log.
- **Agent left versions to me:** per the CLAUDE.md "don't invent" rule, it wrote placeholders for
  action SHAs and the gitleaks checksum and listed what it was unsure about (gitleaks subcommand,
  action inputs) instead of guessing.
- **What went wrong:** my first `git ls-remote` filter kept only annotated tags (`^{}`) and returned
  outdated versions for both actions — the latest releases use lightweight tags.
- **How it was caught:** listing all tags and cross-checking that the major tag (`v7`) points to the
  same commit. Pinning by SHA is only as good as checking that it's the right SHA.
- **Smoke test:** the fixture deliberately contains FAIL findings, so the smoke job asserts the
  *expected* exit codes (triage → 1, diff of the fixture with itself → 0, missing file → 2) rather
  than requiring 0. The agent changed one expected code on purpose to confirm a mismatch fails the job.
- **Green on the first run, so I checked it wasn't vacuous:** gitleaks scanned 10/10 commits
  (matches `git rev-list --count HEAD`), the 3.11 matrix job really ran CPython 3.11.18, and the
  smoke job checked all three exit codes. A check that can't fail checks nothing.