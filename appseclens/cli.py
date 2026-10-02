import argparse
import logging
from pathlib import Path

from .http_client import HTTPClient
from .logger import configure_logging
from .reporter import build_summary, save_html, save_json
from .scanner import WebAppScanner, normalize_url


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "AppSecLens - Passive Web Application "
            "Security Posture Scanner"
        )
    )

    target_group = parser.add_mutually_exclusive_group(
        required=True
    )

    target_group.add_argument(
        "-u",
        "--url",
        help="Scan a single URL"
    )

    target_group.add_argument(
        "-f",
        "--file",
        help="Read target URLs from a text file"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=5,
        help="Number of concurrent workers (default: 5)"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8,
        help="HTTP timeout in seconds (default: 8)"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="reports",
        help="Output directory (default: reports)"
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser.parse_args()


def load_targets(args) -> list[str]:
    """Load targets from URL or file."""

    if args.url:

        return [args.url]

    target_file = Path(args.file)

    if not target_file.exists():

        raise FileNotFoundError(
            f"Target file not found: {target_file}"
        )

    targets = []

    for line in target_file.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        targets.append(line)

    return targets


def main() -> int:
    """Main CLI entry point."""

    args = parse_arguments()

    logger = configure_logging(
        verbose=args.verbose
    )

    try:

        raw_targets = load_targets(args)

        targets = []

        for target in raw_targets:

            normalized = normalize_url(target)

            if normalized:
                targets.append(normalized)

        # Remove duplicates while preserving order
        targets = list(dict.fromkeys(targets))

        if not targets:

            logger.error("No valid targets supplied.")
            return 1

        workers = max(
            1,
            min(args.workers, 20)
        )

        client = HTTPClient(
            timeout=args.timeout,
            verify_tls=not args.insecure
        )

        scanner = WebAppScanner(
            client=client,
            workers=workers
        )

        logger.info(
            "Starting AppSecLens scan against %d target(s)",
            len(targets)
        )

        results = scanner.scan_many(targets)

        summary = build_summary(results)

        print("\n=== AppSecLens Summary ===")

        print(
            f"Critical : {summary['CRITICAL']}"
        )

        print(
            f"High     : {summary['HIGH']}"
        )

        print(
            f"Medium   : {summary['MEDIUM']}"
        )

        print(
            f"Low      : {summary['LOW']}"
        )

        print(
            f"Info     : {summary['INFO']}"
        )

        print("\n=== Target Results ===")

        for result in results:

            print(
                f"\n{result.url}"
                f" -> {result.status_code or 'ERROR'}"
            )

            if result.final_url:

                print(
                    f"Final URL: {result.final_url}"
                )

            if result.elapsed_ms is not None:

                print(
                    f"Response Time: "
                    f"{result.elapsed_ms:.2f} ms"
                )

            if result.findings:

                for finding in result.findings:

                    print(
                        f"  [{finding.severity}] "
                        f"{finding.title}"
                    )

            else:

                print("  No findings detected.")

            if result.errors:

                for error in result.errors:

                    print(
                        f"  [ERROR] {error}"
                    )

        json_path = save_json(
            results,
            args.output
        )

        html_path = save_html(
            results,
            args.output
        )

        logger.info(
            "JSON report saved to %s",
            json_path
        )

        logger.info(
            "HTML report saved to %s",
            html_path
        )

        return 0

    except Exception as exc:

        logger.exception(
            "Application error: %s",
            exc
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
