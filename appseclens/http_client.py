import logging
import time

import requests


class HTTPClient:
    """HTTP client used by AppSecLens."""

    def __init__(
        self,
        timeout: float = 8.0,
        verify_tls: bool = True
    ):
        self.timeout = timeout
        self.verify_tls = verify_tls

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "AppSecLens/1.0 (Authorized Security Testing)"
        })

        self.logger = logging.getLogger("appseclens")

    def get(self, url: str):
        """
        Perform a GET request.

        Returns:
            response, elapsed_ms, error
        """

        start_time = time.perf_counter()

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_tls
            )

            elapsed_ms = (
                time.perf_counter() - start_time
            ) * 1000

            return response, elapsed_ms, None

        except requests.exceptions.Timeout as exc:

            elapsed_ms = (
                time.perf_counter() - start_time
            ) * 1000

            error = f"Request timeout: {exc}"

            self.logger.error(
                "%s -> %s",
                url,
                error
            )

            return None, elapsed_ms, error

        except requests.exceptions.ConnectionError as exc:

            elapsed_ms = (
                time.perf_counter() - start_time
            ) * 1000

            error = f"Connection error: {exc}"

            self.logger.error(
                "%s -> %s",
                url,
                error
            )

            return None, elapsed_ms, error

        except requests.exceptions.RequestException as exc:

            elapsed_ms = (
                time.perf_counter() - start_time
            ) * 1000

            error = f"HTTP request failed: {exc}"

            self.logger.error(
                "%s -> %s",
                url,
                error
            )

            return None, elapsed_ms, error
