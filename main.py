from spoof_checker import SPFChecker, DMARCChecker

if __name__ == "__main__":
    # create an instance of the SPFChecker class
    spf_checker = SPFChecker()
    dmarc_checker = DMARCChecker()

    # check a domain for SPF compliance
    domain = "deepstrat.in"
    if spf_checker.check(domain):
        print(f"{domain} is SPF compliant")
    else:
        print(f"{domain} is not SPF compliant")

    if spf_checker.check_spf_published(domain):
        print("SPF record found")
    else:
        print("No SPF record found")

    if spf_checker.check_spf_deprecated(domain):
        print("No deprecated SPF record found")

    if spf_checker.check_spf_included_lookups(domain):
        print("All include lookups are valid")
    else:
        print("Invalid include lookups found")

    if spf_checker.check_spf_mx_resource_records(domain):
        print("All MX resource records are included")
    else:
        print("MX resource records missing")

    if spf_checker.check_spf_type_ptr(domain):
        print("SPF record contains a PTR type")
    else:
        print("No PTR type found in SPF record")

    if dmarc_checker.check_dmarc(domain):
        print("DMARC record found")
    else:
        print("No DMARC record found")
