from abc import ABC, abstractmethod

import dns.resolver
from dnslib import QTYPE


class spoof_checker(ABC):
    @abstractmethod
    def check(self, domain) -> bool:
        pass


class SPFChecker(spoof_checker):
    def check(self, domain) -> bool:
        return (
            self.check_spf_published(domain)
            and self.check_spf_deprecated(domain)
            and self.check_spf_included_lookups(domain)
            and self.check_spf_mx_resource_records(domain)
            and self.check_spf_type_ptr(domain)
        )

    """Check if domain has a published SPF record"""

    def check_spf_published(self, domain) -> bool:
        try:
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" in record.strings[0].decode():
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    """Check if domain has a deprecated SPF record"""

    def check_spf_deprecated(self, domain) -> bool:
        try:
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" not in record.strings[0].decode():
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    """Check if included lookups in domain's SPF record are valid"""

    def check_spf_included_lookups(self, domain) -> bool:
        try:
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for spf_part in spf_parts:
                        if spf_part.startswith("include:"):
                            include_domain = spf_part.split(":")[1]
                            if not self.check_spf_published(include_domain):
                                return False
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    """Check if domain's SPF record includes all MX resource records"""

    def check_spf_mx_resource_records(self, domain) -> bool:
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for mx_record in mx_records:
                        mx_hostname = mx_record.exchange.to_text().rstrip(".")
                        if "mx:" + mx_hostname not in spf_parts:
                            return False
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    """Check if domain's SPF record includes a valid ptr mechanism"""

    def check_spf_type_ptr(self, domain) -> bool:
        try:
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for spf_part in spf_parts:
                        if spf_part.startswith("ptr:"):
                            ptr_domain = spf_part.split(":")[1]
                            ptr_record = dns.resolver.resolve(ptr_domain, "PTR")
                            for record in ptr_record:
                                if domain in record.to_text():
                                    return True
                    return False
        except dns.resolver.NoAnswer:
            pass
        return False


class DMARCChecker(spoof_checker):
    def check(self, domain) -> bool:
        return self.check_dmarc(domain)

    """Check DMARC Records"""

    def check_dmarc(self, domain) -> bool:
        try:
            # Query for DMARC record
            query = "_dmarc." + domain
            response = dns.resolver.resolve(query, QTYPE.TXT)

            # Parse DMARC record
            record = response.rrset.to_text()
            record = record.replace('" "', ";")  # Replace separator
            record = record.replace('"', "")  # Remove quotes
            fields = record.split(";")

            # Check DMARC policy
            for field in fields:
                if field.startswith("p="):
                    policy = field[2:]
                    if policy == "none":
                        return False
                    elif policy == "quarantine" or policy == "reject":
                        return True
                    else:
                        return False

            # DMARC policy not found
            return False

        except dns.resolver.NXDOMAIN:
            # No DMARC record found
            return False

        except dns.resolver.Timeout:
            # DNS query timed out
            return False

        except Exception as e:
            # Other DNS query errors
            print("Error:", e)
            return False
