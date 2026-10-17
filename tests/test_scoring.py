"""Run with:  python -m unittest discover -s tests"""

import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ukphish.config import load_settings  # noqa: E402
from ukphish.defang import defang, refang  # noqa: E402
from ukphish.pipeline import Pipeline  # noqa: E402
from ukphish.scoring import osa_distance, score_domain  # noqa: E402
from ukphish.storage import DetectionStore  # noqa: E402

SETTINGS = load_settings()
ALERT = SETTINGS.thresholds["alert"]
STORE = SETTINGS.thresholds["store"]


class TestScoring(unittest.TestCase):
    def test_legit_domains_are_allowlisted(self):
        for d in ["barclays.co.uk", "online.lloydsbank.com", "www.monzo.com"]:
            self.assertTrue(score_domain(d, SETTINGS).allowlisted, d)

    def test_obvious_phishing_alerts(self):
        r = score_domain("barclays-secure-verify.top", SETTINGS)
        self.assertEqual(r.brand, "Barclays")
        self.assertGreaterEqual(r.score, ALERT)

    def test_digit_homoglyph(self):
        r = score_domain("natw3st-login.com", SETTINGS)
        self.assertEqual(r.brand, "NatWest")
        self.assertGreaterEqual(r.score, ALERT)

    def test_multichar_homoglyph(self):
        r = score_domain("bardays-payee.com", SETTINGS)  # 'cl' -> 'd'
        self.assertEqual(r.brand, "Barclays")

    def test_typosquat(self):
        r = score_domain("santnader.co", SETTINGS)
        self.assertEqual(r.brand, "Santander UK")
        self.assertTrue(any("edit" in reason for reason in r.reasons))

    def test_punycode(self):
        # 'mоnzo' with a Cyrillic 'о'
        puny = "mоnzo".encode("idna").decode()
        r = score_domain(f"{puny}.com", SETTINGS)
        self.assertEqual(r.brand, "Monzo")
        self.assertTrue(any("punycode" in reason for reason in r.reasons))

    def test_wildcard_and_case(self):
        r = score_domain("*.HSBC-Account-Update.XYZ", SETTINGS)
        self.assertEqual(r.domain, "hsbc-account-update.xyz")
        self.assertGreaterEqual(r.score, ALERT)

    def test_generic_words_without_brand_stay_below_store(self):
        r = score_domain("secure-login-verify.top", SETTINGS)
        self.assertIsNone(r.brand)
        self.assertLess(r.score, STORE)

    def test_unrelated_domain(self):
        r = score_domain("example.org", SETTINGS)
        self.assertEqual(r.score, 0)

    def test_osa_distance(self):
        self.assertEqual(osa_distance("barclasy", "barclays"), 1)
        self.assertEqual(osa_distance("monzo", "monzo"), 0)


class TestDefang(unittest.TestCase):
    def test_roundtrip(self):
        url = "https://barclays-verify.com/login"
        self.assertEqual(defang(url), "hxxps://barclays-verify[.]com/login")
        self.assertEqual(refang(defang(url)), url)


class TestPipeline(unittest.TestCase):
    def test_store_and_dedupe(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DetectionStore(Path(tmp) / "t.db")
            pipe = Pipeline(SETTINGS, store)
            with unittest.mock.patch("builtins.print"):
                pipe.process("revolut-refund-support.shop", "test")
                pipe.process("revolut-refund-support.shop", "test")
            pipe.process("example.org", "test")
            rows = store.top()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["hits"], 2)


if __name__ == "__main__":
    unittest.main()
