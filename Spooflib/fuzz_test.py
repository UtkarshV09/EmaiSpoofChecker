import string
from hypothesis import settings, strategies as st, given
import dns.resolver
from spoof_checker import SPFChecker, DMARCChecker


def domain_name_strategy() -> st.SearchStrategy[str]:
    tlds = [".com", ".org", ".net", ".io", ".in"]
    label = st.text(alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=63).filter(
        lambda x: x[0] != '-' and x[-1] != '-'
    )
    domain = st.lists(label, min_size=1, max_size=5).map(".".join)
    return st.tuples(domain, st.sampled_from(tlds)).map(lambda x: x[0] + x[1])


@settings(deadline=1000)  # Increase the deadline to 1000 ms
@given(domain_name_strategy())
def test_spf_checker(domain):
    spf_checker = SPFChecker()
    try:
        result = spf_checker.check(domain)
        print(f"SPF check result for {domain}: {result}")

        # Add assertions to check whether the result is correct
        assert isinstance(result, bool), f"Invalid result type: {type(result)}"

    except dns.resolver.NXDOMAIN:
        print(f"Domain does not exist: {domain}")

    except Exception as e:
        raise AssertionError(f"Unexpected exception: {e}")


@settings(deadline=1000)  # Increase the deadline to 1000 ms
@given(domain_name_strategy())
def test_dmarc_checker(domain):
    dmarc_checker = DMARCChecker()
    try:
        result = dmarc_checker.check(domain)
        print(f"DMARC check result for {domain}: {result}")

        # Add assertions to check whether the result is correct
        assert isinstance(result, bool), f"Invalid result type: {type(result)}"

    except dns.resolver.NXDOMAIN:
        print(f"Domain does not exist: {domain}")

    except Exception as e:
        raise AssertionError(f"Unexpected exception: {e}")


if __name__ == "__main__":
    for _ in range(5):
        test_spf_checker()
        test_dmarc_checker()
