from typing import List
from cerberus.models import PageResponse, Finding, Severity
from cerberus.rules.base import BaseRule

class SecurityHeadersRule(BaseRule):
    rule_id = "SEC-001"
    name = "Missing Security Headers"

    REQUIRED_HEADERS = {
        "content-security-policy": Severity.MEDIUM,
        "x-frame-options": Severity.LOW,
        "strict-transport-security": Severity.MEDIUM,
        "x-content-type-options": Severity.LOW,
    }

    async def analyze(self, response: PageResponse) -> List[Finding]:
        findings = []
        lowered_headers = {k.lower(): v for k, v in response.headers.items()}

        for header, severity in self.REQUIRED_HEADERS.items():
            if header not in lowered_headers:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=f"Missing Header: {header.upper()}",
                        severity=severity,
                        description=f"The server did not return a {header} security header.",
                        url=response.url,
                    )
                )
        return findings