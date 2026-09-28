import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import privacy_scan as ps  # noqa: E402


def cats(findings):
    return sorted({f.category for f in findings})


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.det = ps.Detectors.build()

    def hits(self, text):
        return sorted({c for c, _, _ in self.det.scan_text(text)})

    def test_private_ips_flagged_public_and_docs_ranges_not(self):
        self.assertEqual(self.hits("nas at 192.168.1.20 and 10.0.0.5"), ["private-ipv4"])
        self.assertEqual(self.hits("172.20.1.1"), ["private-ipv4"])
        self.assertEqual(self.hits("docs use 192.0.2.10 and 8.8.8.8"), [])
        self.assertEqual(self.hits("172.32.0.1 is public"), [])

    def test_windows_domain_sid(self):
        self.assertEqual(self.hits("owner S-1-5-21-1111111-2222222-3333333-1001"), ["windows-sid"])
        self.assertEqual(self.hits("builtin S-1-5-32-556 and S-1-5-18"), [])

    def test_email_ignores_documentation_and_noreply(self):
        self.assertEqual(self.hits("jane.doe@corp-internal.com"), ["email"])
        self.assertEqual(self.hits("sam@example.com 1+x@users.noreply.github.com"), [])

    def test_key_material(self):
        self.assertIn("private-key", self.hits("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertIn("aws-access-key", self.hits("AKIA" + "ABCDEFGHIJKLMNOP"))  # built at runtime: fake fixture
        wg = "[Interface]\nPrivateKey = " + "A" * 43 + "=\n"
        self.assertIn("wireguard-key-assignment", self.hits(wg))
        self.assertIn("secret-assignment", self.hits("api_key = " + '"' + "fake" + "value1234" + '"'))  # fake fixture
        self.assertEqual(self.hits('api_key = os.environ["API_KEY"]'), [])

    def test_disable_builtin(self):
        det = ps.Detectors.build(disable=["email"])
        self.assertEqual(sorted({c for c, _, _ in det.scan_text("a@corp.com")}), [])


class TermsTests(unittest.TestCase):
    def test_terms_plain_and_regex(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\nAcme Widgets\nre:\\bSRV-[0-9]{3}\\b\n\n")
        try:
            det = ps.Detectors.build(fh.name)
            found = [c for c, _, _ in det.scan_text("acme widgets on SRV-042, not SRV-42")]
            self.assertEqual(found.count("term"), 2)
        finally:
            os.unlink(fh.name)

    def test_inline_flags_in_terms(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("re:(?i)\\bfileserver\\d+\\b\nre:\\bSRV-1\\b\n")
        try:
            det = ps.Detectors.build(fh.name)
            found = [c for c, _, _ in det.scan_text("FILESERVER01 and srv-1")]
            self.assertEqual(found, ["term", "term"])
        finally:
            os.unlink(fh.name)

    def test_bad_regex_fails_fast(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("re:([unclosed\n")
        try:
            with self.assertRaises(Exception):
                ps.load_terms(fh.name)
        finally:
            os.unlink(fh.name)


class ScanTests(unittest.TestCase):
    def _git(self, repo, *args):
        subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True)

    def test_git_history_catches_deleted_secret_and_commit_email(self):
        with tempfile.TemporaryDirectory() as repo:
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.name", "Test")
            self._git(repo, "config", "user.email", "1+test@users.noreply.github.com")
            with open(os.path.join(repo, "cfg.txt"), "w") as fh:
                fh.write("server = 10.1.2.3\n")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-qm", "add")
            with open(os.path.join(repo, "cfg.txt"), "w") as fh:
                fh.write("server = <redacted>\n")
            self._git(repo, "commit", "-qam", "remove")
            self._git(repo, "-c", "user.email=leak@corp-internal.com", "commit", "-q", "--allow-empty", "-m", "oops")
            findings = ps.scan_git(repo, ps.Detectors.build())
            self.assertEqual(cats(findings), ["commit-email", "private-ipv4"])
            self.assertTrue(all(f.match is None for f in findings), "matches must be hidden by default")

    def test_dir_scan_skips_binary(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "page.html"), "w") as fh:
                fh.write("<p>call ops@corp-internal.com</p>")
            with open(os.path.join(d, "img.png"), "wb") as fh:
                fh.write(b"\x89PNG\0\0 10.0.0.1")
            findings = ps.scan_dir(d, ps.Detectors.build())
            self.assertEqual([(f.location, f.category) for f in findings], [("page.html", "email")])

    def test_exclude_glob(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tests"))
            with open(os.path.join(d, "tests", "fixture.txt"), "w") as fh:
                fh.write("10.1.1.1")
            self.assertEqual(ps.scan_dir(d, ps.Detectors.build(), exclude=["tests/*"]), [])
            self.assertEqual(len(ps.scan_dir(d, ps.Detectors.build())), 1)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(ps.main(["dir", d]), 0)
            with open(os.path.join(d, "x.txt"), "w") as fh:
                fh.write("10.9.9.9")
            self.assertEqual(ps.main(["dir", d]), 1)


if __name__ == "__main__":
    unittest.main()
