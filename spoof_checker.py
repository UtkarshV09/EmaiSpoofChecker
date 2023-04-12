from abc import ABC, abstractmethod

import dns.resolver
from dnslib import QTYPE


class spoof_checker(ABC):
    @abstractmethod
    def check(self, domain: str) -> bool:
        pass

    def get_spf_record(self, domain: str) -> str:
        try:
            spf_record = dns.resolver.resolve(domain, "TXT")
            for record in spf_record:
                if "v=spf1" in record.strings[0].decode():
                    return record.strings[0].decode()
        except dns.resolver.NoAnswer:
            pass
        return ""

    def check_spf_published(self, domain: str) -> bool:
        spf_record = self.get_spf_record(domain)
        if not spf_record:
            return False
        return "v=spf1" in spf_record

    def check_included_lookups(self, spf_parts, check_spf):
        for spf_part in spf_parts:
            if spf_part.startswith("include:"):
                include_domain = spf_part.split(":")[1]
                if not check_spf(include_domain):
                    return False
        return True

    def check_mx_resource_records(self, domain: str, mx_records):
        spf_parts = self.get_spf_record(domain).split()
        for spf_part in spf_parts:
            if spf_part.startswith("mx:"):
                mx_hostname = spf_part.split(":")[1]
                if mx_hostname in mx_records:
                    return True
        return False

    def check_type_ptr(self, domain: str):
        spf_parts = self.get_spf_record(domain).split()
        for spf_part in spf_parts:
            if spf_part.startswith("ptr:"):
                ptr_domain = spf_part.split(":")[1]
                try:
                    ptr_record = dns.resolver.resolve(ptr_domain, "PTR")
                    for record in ptr_record:
                        if domain in record.to_text():
                            return True
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
        return False


class SPFChecker(spoof_checker):
    def check(self, domain: str) -> bool:
        spf_record = self.get_spf_record(domain)
        if not spf_record:
            return False
        mx_records = [
            str(mx.exchange).rstrip(".") for mx in dns.resolver.resolve(domain, "MX")
        ]
        spf_parts = spf_record.split()
        return (
            "v=spf1" in spf_parts
            and not "v=spf1" not in spf_parts
            and self.check_included_lookups(spf_parts, self.check_spf_published)
            and self.check_mx_resource_records(domain, mx_records)
            and self.check_type_ptr(domain)
        )


class DMARCChecker(spoof_checker):
    def check(self, domain: str) -> bool:
        return self.check_dmarc(domain)

    """Check DMARC Records"""

    def check_dmarc(self, domain: str) -> bool:
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
