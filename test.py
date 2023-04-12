import unittest

from spoof_checker import DMARCChecker, SPFChecker


class TestSPFChecker(unittest.TestCase):
    def test_check_spf_published(self):
        checker = SPFChecker()
        self.assertTrue(checker.check_spf_published("truecaller.com"))

    # def test_check_spf_deprecated(self):
    #     checker = SPFChecker()
    #     self.assertFalse(checker.check_spf_deprecated("thedialogue.co"))

    def test_check_included_lookups(self):
        checker = SPFChecker()
        self.assertTrue(checker.check_included_lookups("deepstrat.in"))

    def test_check_spf_mx_resource_records(self):
        checker = SPFChecker()
        self.assertTrue(checker.check_mx_resource_records("deepstrat.in"))

    def test_check_spf_type_ptr(self):
        checker = SPFChecker()
        self.assertFalse(checker.check_type_ptr("deepstrat.in"))


class TestDMARCChecker(unittest.TestCase):
    def test_check_dmarc(self):
        checker = DMARCChecker()
        self.assertTrue(checker.check("email.gov.in"))


if __name__ == "__main__":
    unittest.main()
