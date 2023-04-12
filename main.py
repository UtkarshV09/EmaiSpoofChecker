import dns.resolver
from spoof_checker import DMARCChecker, SPFChecker


def main():
    spf_checker = SPFChecker()
    dmarc_checker = DMARCChecker()

    # Check a domain for SPF compliance
    domain = "deepstrat.in"
    if spf_checker.check(domain):
        print(f"{domain} is SPF compliant")
    else:
        print(f"{domain} is not SPF compliant")

    if spf_checker.check_spf_published(domain):
        print("SPF record found")
    else:
        print("No SPF record found")

    if spf_checker.check_included_lookups(
        spf_checker.get_spf_record(domain).split(), spf_checker.check_spf_published
    ):
        print("All include lookups are valid")
    else:
        print("Invalid include lookups found")

    if spf_checker.check_mx_resource_records(
        domain,
        [str(mx.exchange).rstrip(".") for mx in dns.resolver.resolve(domain, "MX")],
    ):
        print("All MX resource records are included")
    else:
        print("MX resource records missing")

    if spf_checker.check_type_ptr(domain):
        print("SPF record contains a PTR type")
    else:
        print("No PTR type found in SPF record")

    if dmarc_checker.check_dmarc(domain):
        print("DMARC record found")
    else:
        print("No DMARC record found")


if __name__ == "__main__":
    main()
