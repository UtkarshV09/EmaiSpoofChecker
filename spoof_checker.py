import dns.resolver
# from emailprotectionslib import spf, dmarc
from abc import ABC, abstractmethod


class spoof_checker(ABC):

    @abstractmethod
    def check(self, domain):
        pass


class SPFChecker(spoof_checker):

    def check(self, domain):
        return (self.check_spf_published(domain) and
                self.check_spf_deprecated(domain) and
                self.check_spf_included_lookups(domain) and
                self.check_spf_mx_resource_records(domain) and
                self.check_spf_type_ptr(domain))

    def check_spf_published(self, domain):
        # Check if domain has a published SPF record
        try:
            spf_record = dns.resolver.resolve(domain, 'TXT')
            for record in spf_record:
                if 'v=spf1' in record.strings[0].decode():
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    def check_spf_deprecated(self, domain):
        # Check if domain has a deprecated SPF record
        try:
            spf_record = dns.resolver.resolve(domain, 'TXT')
            for record in spf_record:
                if 'v=spf1' not in record.strings[0].decode():
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    def check_spf_included_lookups(self, domain):
        # Check if included lookups in domain's SPF record are valid
        try:
            spf_record = dns.resolver.resolve(domain, 'TXT')
            for record in spf_record:
                if 'v=spf1' in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for spf_part in spf_parts:
                        if spf_part.startswith('include:'):
                            include_domain = spf_part.split(':')[1]
                            if not self.check_spf_published(include_domain):
                                return False
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    def check_spf_mx_resource_records(self, domain):
        # Check if domain's SPF record includes all MX resource records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            spf_record = dns.resolver.resolve(domain, 'TXT')
            for record in spf_record:
                if 'v=spf1' in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for mx_record in mx_records:
                        mx_hostname = mx_record.exchange.to_text().rstrip('.')
                        if 'mx:' + mx_hostname not in spf_parts:
                            return False
                    return True
        except dns.resolver.NoAnswer:
            pass
        return False

    def check_spf_type_ptr(self, domain):
        # Check if domain's SPF record includes a valid ptr mechanism
        try:
            spf_record = dns.resolver.resolve(domain, 'TXT')
            for record in spf_record:
                if 'v=spf1' in record.strings[0].decode():
                    spf_parts = record.strings[0].decode().split()
                    for spf_part in spf_parts:
                        if spf_part.startswith('ptr:'):
                            ptr_domain = spf_part.split(':')[1]
                            ptr_record = dns.resolver.resolve(ptr_domain, 'PTR')
                            for record in ptr_record:
                                if domain in record.to_text():
                                    return True
                    return False
        except dns.resolver.NoAnswer:
            pass
        return False
