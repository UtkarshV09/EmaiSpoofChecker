import unittest

from spooflib.spoof_checker import SPFChecker


class TestSPFChecker(unittest.TestCase):
    def test_check_spf_published(self):
        checker = SPFChecker()
        self.assertTrue(checker.check_spf_published("truecaller.com"))

    def test_check_included_lookups(self):
        checker = SPFChecker()
        self.assertTrue(
            checker.check_included_lookups("truecaller.com", check_spf=True)
        )

    # def test_check_spf_mx_resource_records(self):
    #     checker = SPFChecker()
    #     self.assertTrue(checker.check_mx_resource_records("cloudflare", mx_records=True))

    def test_check_spf_type_ptr(self):
        checker = SPFChecker()
        self.assertFalse(checker.check_type_ptr("email.gov.in"))


if __name__ == "__main__":
    unittest.main()
