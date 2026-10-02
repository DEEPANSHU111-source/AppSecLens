import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .http_client import HTTPClient
from .models import ScanResult


class BaseScanner:
    """Base class for scanners."""

    def __init__(
        self,
        client: HTTPClient,
        workers: int = 5
    ):
        self.client = client
        self.workers = workers
        self.logger = logging.getLogger("appseclens")

    def scan_one(self, url: str) -> ScanResult:
        """Scan one URL."""

        raise NotImplementedError(
            "Child scanner must implement scan_one()"
        )

    def scan_many(self, urls: list[str]) -> list[ScanResult]:
        """Scan multiple URLs concurrently."""

        results = []

        with ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:

            future_map = {
                executor.submit(
                    self.scan_one,
                    url
                ): url
                for url in urls
            }

            for future in as_completed(future_map):

                url = future_map[future]

                try:
                    result = future.result()
                    results.append(result)

                except Exception as exc:

                    self.logger.exception(
                        "Unexpected error while scanning %s",
                        url
                    )

                    results.append(
                        ScanResult(
                            url=url,
                            errors=[str(exc)]
                        )
                    )

        return sorted(
            results,
            key=lambda result: result.url
        )


class WebAppScanner(BaseScanner):
    """Scanner for passive web application assessment."""

    def scan_one(self, url: str) -> ScanResult:

        result = ScanResult(url=url)

        response, elapsed_ms, error = self.client.get(url)

        result.elapsed_ms = elapsed_ms

        if response is None:

            result.errors.append(
                error or "No response received"
            )

            return result

        result.final_url = response.url
        result.status_code = response.status_code

        result.server = response.headers.get(
            "Server",
            ""
        )

        result.content_type = response.headers.get(
            "Content-Type",
            ""
        )

        from .checks import run_all_checks

        result.findings = run_all_checks(response)

        return result


def normalize_url(url: str) -> str:
    """Normalize and validate a target URL."""

    url = url.strip()

    if not url:
        return ""

    parsed = urlparse(url)

    if not parsed.scheme:
        return "https://" + url

    if parsed.scheme not in {
        "http",
        "https"
    }:

        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme}"
        )

    return url
