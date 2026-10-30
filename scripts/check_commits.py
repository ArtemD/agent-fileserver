#!/usr/bin/env python3
"""Every change has an issue: check commit messages, issue links and author privacy.

  python3 scripts/check_commits.py --message-file FILE        # .githooks/commit-msg
  python3 scripts/check_commits.py --verify-issues -- REVS    # .githooks/pre-push and CI
  python3 scripts/check_commits.py --self-test

REVS are `git log` revisions, e.g. `origin/main..HEAD`. A commit passes when:
- the subject is at most 72 characters, starts with a capital letter, has no
  trailing period and is not a fixup!/squash!/WIP commit;
- a blank line follows and a body explains why (body lines wrap at 72, except
  URLs, indented lines and trailers);
- it references an issue on its own line: `Fixes #N` (closes it when pushed to
  main), `Closes #N`, `Resolves #N` or `Refs #N`; a security fix may reference
  its private advisory instead (`Refs GHSA-xxxx-xxxx-xxxx`);
- author and committer emails are GitHub noreply addresses (public repository);
- docs stay in sync: a commit that changes code, deployment, scripts or CI also
  changes README.md, AGENTS.md, SECURITY.md or docs/, or says why not on its own
  line: `Docs: unchanged, <reason>`.
Merge commits and GitHub bot commits (Dependabot) are exempt.

--verify-issues also asks GitHub (via `gh`) that each referenced number is an
issue, not a pull request, and that it fills every required field of one of the
.github/ISSUE_TEMPLATE forms. Stdlib only; exit status 1 on any failure.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / ".github" / "ISSUE_TEMPLATE"
MAX = 72
ISSUE_REF = re.compile(r"^(?:Fixes|Closes|Resolves|Refs) #(\d+)\b", re.M)
ADVISORY_REF = re.compile(r"^(?:Fixes|Refs) GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.M)
TRAILER = re.compile(r"^[A-Za-z][A-Za-z-]*: \S")
BOT = re.compile(r"^\d+\+[\w-]+\[bot\]@users\.noreply\.github\.com$")
CODE = re.compile(r"^(?!.*_test\.go$)[^/]+\.go$|^(compose[^/]*\.yaml|Dockerfile|\.env\.example|go\.mod)$"
                  r"|^(deploy|scripts|\.githooks|\.github)/")
DOCS = re.compile(r"^(README|AGENTS|SECURITY)\.md$|^docs/")
DOCS_WAIVER = re.compile(r"^Docs: unchanged, \S", re.M)
SCISSORS = "# ------------------------ >8 ------------------------"


def strip_comments(message):
    """What git keeps after `commit --cleanup=strip`: no comments, no scissors tail."""
    message = message.split(SCISSORS, 1)[0]
    return "\n".join(line for line in message.splitlines() if not line.startswith("#"))


def message_problems(message):
    """Return (problems, issue numbers) for one commit message."""
    lines = message.strip("\n").splitlines()
    problems = []
    subject = lines[0] if lines else ""
    if not subject.strip():
        return ["empty commit message"], []
    if len(subject) > MAX:
        problems.append(f"subject is {len(subject)} characters (max {MAX})")
    if not subject[0].isupper():
        problems.append("subject must start with a capital letter (imperative: 'Fix …', 'Add …')")
    if subject.endswith("."):
        problems.append("subject must not end with a period")
    if re.match(r"(fixup|squash|amend)!|wip\b", subject, re.I):
        problems.append("fixup!/squash!/WIP commits must be squashed before pushing")
    if len(lines) < 3 or lines[1].strip():
        problems.append("the second line must be blank, followed by a body explaining why")
    body = lines[2:]
    prose = [l for l in body if l.strip() and not TRAILER.match(l)
             and not ISSUE_REF.match(l) and not ADVISORY_REF.match(l)]
    if len(lines) >= 3 and not prose:
        problems.append("the body must explain why the change is needed, not only trailers")
    for number, line in enumerate(body, start=3):
        if len(line) > MAX and "://" not in line and not line.startswith((" ", "\t")) \
                and not TRAILER.match(line):
            problems.append(f"line {number} is {len(line)} characters (wrap at {MAX})")
    issues = [int(n) for n in ISSUE_REF.findall(message)]
    if not issues and not ADVISORY_REF.search(message):
        problems.append("no issue reference: add a line 'Fixes #N' (closes it) or 'Refs #N'")
    return problems, issues


def docs_problems(files, message):
    if any(CODE.search(f) for f in files) and not any(DOCS.search(f) for f in files) \
            and not DOCS_WAIVER.search(message):
        return ["changes code, deployment or CI but no docs: update README.md, AGENTS.md "
                "or docs/ in the same commit, or add 'Docs: unchanged, <reason>'"]
    return []


def email_problems(role, email):
    if email.endswith("@users.noreply.github.com") or email == "noreply@github.com":
        return []
    return [f"{role} email is not a GitHub noreply address; this repository is public "
            "(git config user.email ID+LOGIN@users.noreply.github.com)"]


def required_fields(template_text):
    """Labels of required fields in an issue form; they become '### Label' headings."""
    fields, label = [], None
    for line in template_text.splitlines():
        if line.startswith("  - type:"):
            label = None
        elif m := re.match(r"^      label: (.+)$", line):
            label = m.group(1).strip().strip("'\"")
        elif re.match(r"^      required: true\s*$", line) and label:
            fields.append(label)
    return fields


def templates():
    return {p.name: required_fields(p.read_text(encoding="utf-8"))
            for p in sorted(TEMPLATES.glob("*.yml")) if p.name != "config.yml"}


def issue_body_problems(body, forms):
    """An issue passes if it fills every required field of at least one form."""
    sections, current = {}, None
    for line in (body or "").splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    filled = {k for k, v in sections.items()
              if "\n".join(v).strip() not in ("", "_No response_")}
    missing = {name: [f for f in fields if f not in filled] for name, fields in forms.items()}
    if any(not m for m in missing.values()):
        return []
    name, gaps = min(missing.items(), key=lambda item: len(item[1]))
    return [f"issue does not follow a template; closest is {name}, missing: " + ", ".join(gaps)]


class GitHub:
    def __init__(self):
        if not shutil.which("gh"):
            sys.exit("check_commits: --verify-issues needs the GitHub CLI: brew install gh, then gh auth login")
        self.repo = os.environ.get("GITHUB_REPOSITORY") or subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if not self.repo:
            sys.exit("check_commits: could not determine the GitHub repository (is gh authenticated?)")
        self.forms, self.cache = templates(), {}

    def problems(self, number):
        if number not in self.cache:
            result = subprocess.run(["gh", "api", f"repos/{self.repo}/issues/{number}"],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                self.cache[number] = [f"#{number} is not an issue in {self.repo}"]
            else:
                issue = json.loads(result.stdout)
                if "pull_request" in issue:
                    self.cache[number] = [f"#{number} is a pull request; reference its issue"]
                else:
                    self.cache[number] = [f"#{number}: " + p
                                          for p in issue_body_problems(issue.get("body"), self.forms)]
        return self.cache[number]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def ident_email(var):
    m = re.search(r"<([^>]*)>", git("var", var))
    return m.group(1) if m else ""


def check_message_file(path):
    if subprocess.run(["git", "rev-parse", "-q", "--verify", "MERGE_HEAD"], cwd=ROOT,
                      capture_output=True).returncode == 0:
        return 0
    message = strip_comments(Path(path).read_text(encoding="utf-8"))
    problems, _ = message_problems(message)
    problems += docs_problems(git("diff", "--cached", "--name-only").split("\n"), message)
    problems += email_problems("author", ident_email("GIT_AUTHOR_IDENT"))
    problems += email_problems("committer", ident_email("GIT_COMMITTER_IDENT"))
    for p in problems:
        print("commit-msg: " + p, file=sys.stderr)
    if problems:
        print("commit-msg: message kept in .git/COMMIT_EDITMSG; see AGENTS.md 'Git'", file=sys.stderr)
    return 1 if problems else 0


def check_revisions(revs, verify):
    github = GitHub() if verify else None
    log = git("log", "--format=%H%x00%P%x00%ae%x00%ce%x00%B%x1e", *revs)
    failed = checked = 0
    for record in filter(str.strip, log.split("\x1e")):
        sha, parents, author, committer, message = record.lstrip("\n").split("\x00", 4)
        if len(parents.split()) > 1 or BOT.match(author):
            continue
        checked += 1
        problems, issues = message_problems(message)
        problems += email_problems("author", author) + email_problems("committer", committer)
        files = git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha).split("\n")
        problems += docs_problems(files, message)
        if github:
            for number in dict.fromkeys(issues):
                problems += github.problems(number)
        for p in problems:
            print(f"FAIL {sha[:8]} {message.splitlines()[0][:50]!r}: {p}")
        failed += bool(problems)
    print(f"{'FAIL' if failed else 'PASS'}: {checked - failed}/{checked} commits pass"
          f" (issue link{' to a templated issue' if verify else ''}, message format, noreply emails, docs in sync)")
    return 1 if failed else 0


def self_test():
    good = ("Serve release URLs that carry a query string\n\n"
            "forward_auth keeps the visitor's query, so authorize returned 404.\n"
            "See https://example.invalid/a/very/long/url/that/is/allowed/to/exceed/the/limit\n\n"
            "Fixes #12\nCo-Authored-By: Someone Long Enough To Exceed The Wrap Width <noreply@example.invalid>\n")
    assert message_problems(good) == ([], [12]), message_problems(good)
    assert message_problems(good.replace("Fixes #12", "Refs #3\nFixes #4"))[1] == [3, 4]
    assert not message_problems(good.replace("Fixes #12", "Refs GHSA-2x3c-vwrm-q9hj"))[0]
    bad = {
        "no issue reference": good.replace("Fixes #12", ""),
        "subject is": "S" + "x" * 72 + good[good.index("\n"):],
        "capital letter": "s" + good[1:],
        "period": good.replace("string\n", "string.\n", 1),
        "squashed": "fixup! " + good,
        "second line must be blank": good.replace("\n\n", "\n", 1),
        "explain why": "Bump something\n\nFixes #1\n",
        "line 3 is": good.replace("forward_auth", "x" * 80),
        "empty": "\n\n",
        "no issue reference: add": good.replace("Fixes #12", "This fixes #12"),
    }
    for expected, message in bad.items():
        problems = " ".join(message_problems(message)[0])
        assert expected in problems, (expected, problems)
    assert message_problems(strip_comments("# comment\n" + good + "# Please enter\n" + SCISSORS + "\ndiff"))[0] == []
    assert email_problems("author", "47930+ArtemD@users.noreply.github.com") == []
    assert email_problems("committer", "noreply@github.com") == []
    assert email_problems("author", "someone@example.com")
    assert BOT.match("49699333+dependabot[bot]@users.noreply.github.com")
    assert not BOT.match("47930+ArtemD@users.noreply.github.com")
    assert docs_problems(["api.go", "api_test.go"], good)
    assert docs_problems([".github/workflows/test.yml"], good)
    assert not docs_problems(["api.go", "docs/MCP.md"], good)
    assert not docs_problems(["api_test.go", "tests/mcp_live.py"], good)
    assert not docs_problems(["api.go"], good + "Docs: unchanged, internal rename only\n")
    assert not message_problems(good + "Docs: unchanged, internal rename only\n")[0]
    forms = templates()
    assert forms == {
        "bug.yml": ["Summary", "Impact", "Steps to reproduce", "Expected behaviour",
                    "Actual behaviour", "Version"],
        "change.yml": ["Problem", "Proposed change", "Security and boundary impact",
                       "Acceptance criteria"],
    }, forms
    change = "".join(f"### {f}\n\ntext\n\n" for f in forms["change.yml"])
    assert issue_body_problems(change, forms) == []
    assert issue_body_problems(change.replace("### Problem", "### Other"), forms)
    assert issue_body_problems(change.replace("text", "_No response_", 1), forms)
    assert "missing:" in issue_body_problems("", forms)[0]
    print("PASS: check_commits self-test")
    return 0


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--message-file")
    parser.add_argument("--verify-issues", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("revs", nargs="*")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.message_file:
        return check_message_file(args.message_file)
    if not args.revs:
        parser.error("give --message-file, --self-test or git revisions (e.g. -- origin/main..HEAD)")
    return check_revisions(args.revs, args.verify_issues)


if __name__ == "__main__":
    sys.exit(main())
