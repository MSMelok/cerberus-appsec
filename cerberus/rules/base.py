from abc import ABC, abstractmethod
from typing import ClassVar, List
from cerberus.models import PageResponse, Finding

class BaseRule(ABC):
    rule_id: ClassVar[str]
    name: ClassVar[str]

    @abstractmethod
    async def analyze(self, response: PageResponse) -> List[Finding]:
        """Runs security evaluation against fetched response."""
        pass