import secrets
import hashlib
import time
from typing import Tuple, Optional
import dns.resolver
import httpx
from pydantic import BaseModel

class VerificationToken(BaseModel):
    domain: str
    token: str
    created_at: float
    expected_txt_record: str
    expected_file_path: str

class DomainVerifier:
    def __init__(self, prefix: str = "cerberus-verification"):
        self.prefix = prefix

    def generate_challenge(self, domain: str) -> VerificationToken:
        """
        Generates a unique, deterministic token tied to the domain.
        """
        raw_secret = f"{domain}:{time.time()}:{secrets.token_hex(16)}"
        token = hashlib.sha256(raw_secret.encode()).hexdigest()[:32]
        
        return VerificationToken(
            domain=domain,
            token=token,
            created_at=time.time(),
            expected_txt_record=f"{self.prefix}={token}",
            expected_file_path=f"/.well-known/cerberus-check.txt"
        )

    def verify_dns_txt(self, domain: str, expected_token: str) -> Tuple[bool, str]:
        """
        Checks DNS TXT records for the verification string.
        """
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            expected_value = f"{self.prefix}={expected_token}"
            
            for rdata in answers:
                for txt_string in rdata.strings:
                    if txt_string.decode('utf-8') == expected_value:
                        return True, "DNS verification successful."
                        
            return False, f"TXT record '{expected_value}' not found on {domain}."
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False, f"No TXT records found for {domain}."
        except Exception as e:
            return False, f"DNS lookup failed: {str(e)}"

    async def verify_http_file(self, domain: str, expected_token: str) -> Tuple[bool, str]:
        """
        Checks http(s)://domain/.well-known/cerberus-check.txt for the token.
        """
        url = f"https://{domain}/.well-known/cerberus-check.txt"
        
        async with httpx.AsyncClient(verify=True, timeout=5.0) as client:
            try:
                res = await client.get(url)
                if res.status_code == 200 and expected_token in res.text.strip():
                    return True, "HTTP file verification successful."
                return False, f"Verification file found at {url}, but token did not match."
            except httpx.RequestError as e:
                return False, f"Failed to reach {url}: {str(e)}"