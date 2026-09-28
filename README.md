# repo-privacy-scan

[![test](https://github.com/forrestswan3/repo-privacy-scan/actions/workflows/test.yml/badge.svg)](https://github.com/forrestswan3/repo-privacy-scan/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB) ![dependencies](https://img.shields.io/badge/dependencies-none-2C9C95) ![license](https://img.shields.io/badge/license-MIT-0B1F33)

**Find staff names, internal hostnames, private IPs and secrets before a repository or website goes public, including in git history you thought you deleted.**

Secret scanners like gitleaks catch API keys. They don't catch *your* sensitive data: a coworker's name in a test fixture, the office file server's hostname in a comment, or a real street address used as sample data. `repo-privacy-scan` pairs built-in detectors with a **private terms file you keep outside the repo**, and checks three places:

| Command | What it scans |
|---|---|
| `git <repo>` | Every blob on every branch and tag, across full history, plus commit author/committer emails |
| `dir <folder>` | A plain folder, for example a static-site `dist/` build before deploy |
| `urls <list>` | Live pages fetched **logged-out**, checking both HTTP status (e.g. that private repos return 404) and page content |

By default, findings print a **category, location and fingerprint, never the matched text**, so CI logs don't leak what they found.

## Quick start

```bash
# no install: standard library only, Python 3.9+
python privacy_scan.py git  path/to/repo --terms ~/private/company.terms.txt
python privacy_scan.py dir  site/dist    --terms ~/private/company.terms.txt
python privacy_scan.py urls urls.txt     --terms ~/private/company.terms.txt
```

`urls.txt` has one URL per line with the HTTP status you expect:

```text
https://example.github.io/                     200
https://github.com/your-user/private-project   404
```

The exit code is `1` if anything is found (or a URL returns the wrong status), so it works as a CI gate.

| Option | Purpose |
|---|---|
| `--terms FILE` | Your private term list (see below) |
| `--exclude GLOB` | Skip matching paths, e.g. `--exclude 'tests/*'` for deliberate fixtures |
| `--disable NAME` | Turn off a built-in detector |
| `--json` | Machine-readable output |
| `--show-matches` | Print matched text. Local use only, never in CI |

## Built-in detectors

| Category | Catches | Deliberately ignores |
|---|---|---|
| `private-ipv4` | RFC 1918 ranges (10/8, 172.16/12, 192.168/16) | RFC 5737 documentation ranges, public IPs |
| `windows-sid` | Domain and local account SIDs (`S-1-5-21-…`) | Well-known SIDs such as `S-1-5-32-556` |
| `email` | Real-looking addresses | `example.com`, `*.example`, GitHub noreply |
| `private-key`, `aws-access-key`, `wireguard-key-assignment`, `secret-assignment` | Key material and hard-coded credentials | Values read from the environment |
| `commit-email` | Non-noreply identities in commit metadata | GitHub noreply addresses |
| `term` | Anything in your private terms file | — |

## The terms file

Keep it **outside** the repository. `.gitignore` already blocks `*.terms.txt`.

```text
# plain lines are whole-word, case-insensitive
Jane Example
fileserver01
# re: for a regular expression
re:\bEMP-[0-9]{4}\b
```

In GitHub Actions, store the list as an encrypted secret and write it to a temp file at run time. Don't commit it.

## If it finds something

1. **Rotate any real credential first.** Rewriting history doesn't un-leak a key.
2. Make the repository private or take the page down.
3. Rewrite history (for example `git filter-repo --replace-text`), rescan to zero, then force-push.
4. Close pull requests that still reference the old commits, and follow GitHub's guide to [removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## Background

I built the original version to lock down my own portfolio. I scrubbed names, an address and infrastructure details from the full history of several repositories, moved the source to private repos, and verified everything logged-out. This is the reusable, organization-free version of that workflow. More at [forrestswan3.github.io](https://forrestswan3.github.io/work/).

## Tests

```bash
python -m unittest discover -s tests -v
```

CI runs the suite on Python 3.9 and 3.12, then scans this repository with itself.

## License

MIT © Forrest Swan III
