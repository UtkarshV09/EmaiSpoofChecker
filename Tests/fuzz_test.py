import string

from hypothesis import given, settings
from hypothesis import strategies as st
import dns.resolver
from spooflib.spoof_checker import SPFChecker, DMARCChecker


"""Generates a domain name search strategy using TLDs and domain labels"""


def domain_name_strategy() -> st.SearchStrategy[str]:
    tlds = [".com", ".org", ".net", ".io", ".in"]
    label = st.text(
        alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=63
    ).filter(lambda x: x[0] != '-' and x[-1] != '-')
    domain = st.lists(label, min_size=1, max_size=5).map(".".join)
    return st.tuples(domain, st.sampled_from(tlds)).map(lambda x: x[0] + x[1])


""" Test the SPFChecker for the given domain"""


@settings(deadline=1000)
@given(domain_name_strategy())
def test_spf_checker(domain):
    spf_checker = SPFChecker()
    try:
        result = spf_checker.check(domain)
        print(f"SPF check result for {domain}: {result}")

        """Add assertions to check whether the result is correct"""
        assert isinstance(result, bool), f"Invalid result type: {type(result)}"

    except dns.resolver.NXDOMAIN:
        print(f"Domain does not exist: {domain}")

    except Exception as e:
        raise AssertionError(f"Unexpected exception: {e}")


"""Test the DMARCChecker for the given domain"""


@settings(deadline=1000)
@given(domain_name_strategy())
def test_dmarc_checker(domain):
    dmarc_checker = DMARCChecker()
    try:
        result = dmarc_checker.check(domain)
        print(f"DMARC check result for {domain}: {result}")

        """Add assertions to check whether the result is correct"""
        assert isinstance(result, bool), f"Invalid result type: {type(result)}"

    except dns.resolver.NXDOMAIN:
        print(f"Domain does not exist: {domain}")

    except Exception as e:
        raise AssertionError(f"Unexpected exception: {e}")


if __name__ == "__main__":
    for _ in range(5):
        # test_spf_checker()
        test_dmarc_checker()
