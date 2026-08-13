import asyncio
import logging
from typing import List, Set, Type
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

from cerberus.models import PageResponse, Finding
from cerberus.rules.base import BaseRule

logger = logging.getLogger(__name__)

class AsyncScannerEngine:
    def __init__(
        self,
        target_url: str,
        rules: List[BaseRule],
        max_depth: int = 2,
        concurrency: int = 5,
    ):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self.rules = rules
        self.max_depth = max_depth
        self.semaphore = asyncio.Semaphore(concurrency)
        self.visited: Set[str] = set()

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.target_domain or not parsed.netloc

    async def crawl_and_scan(self) -> List[Finding]:
        all_findings: List[Finding] = []
        queue = asyncio.Queue()
        await queue.put((self.target_url, 0))
        self.visited.add(self.target_url)

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            tasks = []
            while not queue.empty():
                url, depth = await queue.get()
                if depth > self.max_depth:
                    continue

                tasks.append(self._process_url(client, url, depth, queue, all_findings))

            await asyncio.gather(*tasks)

        return all_findings

    async def _process_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        queue: asyncio.Queue,
        findings_accumulator: List[Finding],
    ):
        async with self.semaphore:
            try:
                res = await client.get(url)
                soup = BeautifulSoup(res.text, "html.parser")

                # Link extraction
                discovered_links = []
                if depth < self.max_depth:
                    for a_tag in soup.find_all("a", href=True):
                        full_url = urljoin(url, a_tag["href"]).split("#")[0]
                        if self._is_in_scope(full_url) and full_url not in self.visited:
                            self.visited.add(full_url)
                            await queue.put((full_url, depth + 1))
                            discovered_links.append(full_url)

                page_resp = PageResponse(
                    url=str(res.url),
                    status_code=res.status_code,
                    headers=dict(res.headers),
                    body=res.text,
                    discovered_links=discovered_links,
                )

                # Execute rule set concurrently
                for rule in self.rules:
                    rule_findings = await rule.analyze(page_resp)
                    findings_accumulator.extend(rule_findings)

            except asyncio.TimeoutError:
                logger.warning(f"Timeout while fetching {url}")
            except httpx.RequestError as e:
                logger.warning(f"Request error for {url}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error processing {url}: {str(e)}", exc_info=True)