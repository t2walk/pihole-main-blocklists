#!/usr/bin/env python3
"""Build repo-hosted Pi-hole blocklist chunks from a plain URL source file."""

from __future__ import annotations

import argparse
import logging
import os
import traceback

from build_master_blocklist import (
    DEFAULT_CHUNK_DIR,
    DEFAULT_CHUNK_SIZE_MB,
    DEFAULT_OUTPUT,
    DEFAULT_TIMEOUT,
    PiHoleError,
    Source,
    fetch_text,
    split_master_list,
    write_master_list,
)


DEFAULT_SOURCES = "sources.txt"
LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
LOGGER = logging.getLogger("build_repo_blocklist")


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=LOG_FORMAT,
    )


def dedupe_entries_exact(texts: list[str]) -> list[str]:
    """
    Deduplicate blocklist entries without modifying syntax.

    Preserves entries exactly as provided, including:
      ||example.com^
      example.com
      0.0.0.0 example.com
      @@||example.com^

    Only removes exact duplicate lines after trimming surrounding whitespace.
    """
    seen: set[str] = set()
    entries: list[str] = []

    for text in texts:
        for raw_line in text.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith(("#", "!")):
                continue

            if line in seen:
                continue

            seen.add(line)
            entries.append(line)

    return entries


def read_source_urls(path: str) -> list[str]:
    LOGGER.info("Reading source URL file: %s", path)

    if not path:
        raise PiHoleError("Source URL file path is empty")

    if not os.path.exists(path):
        raise PiHoleError(f"Missing source URL file: {path}")

    if not os.path.isfile(path):
        raise PiHoleError(f"Source URL path is not a file: {path}")

    urls: list[str] = []
    seen: set[str] = set()

    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                if not line.startswith(("http://", "https://")):
                    raise PiHoleError(f"{path}:{line_number} is not an HTTP(S) URL: {line}")

                if line in seen:
                    LOGGER.debug("Skipping duplicate source URL at %s:%s: %s", path, line_number, line)
                    continue

                seen.add(line)
                urls.append(line)
    except OSError as exc:
        raise PiHoleError(f"Could not read source URL file {path}: {exc}") from exc

    if not urls:
        raise PiHoleError(f"No source URLs found in {path}")

    LOGGER.info("Loaded %d unique source URL(s)", len(urls))
    return urls


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build de-duplicated repo blocklist chunks from a URL source file."
    )
    parser.add_argument("--sources", default=DEFAULT_SOURCES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--chunk-dir", default=DEFAULT_CHUNK_DIR)
    parser.add_argument("--chunk-size-mb", type=int, default=DEFAULT_CHUNK_SIZE_MB)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--fail-on-source-error",
        action="store_true",
        help="Exit non-zero if any upstream source fails to download.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    LOGGER.debug("Validating CLI arguments")

    if args.chunk_size_mb <= 0:
        raise PiHoleError("--chunk-size-mb must be greater than 0")

    if args.timeout <= 0:
        raise PiHoleError("--timeout must be greater than 0")

    if not args.output:
        raise PiHoleError("--output cannot be empty")

    if not args.chunk_dir:
        raise PiHoleError("--chunk-dir cannot be empty")


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    LOGGER.info("Starting repo blocklist build")
    LOGGER.debug("Runtime arguments: %s", vars(args))

    try:
        validate_args(args)

        source_urls = read_source_urls(args.sources)
        sources = [Source(url=url) for url in source_urls]

        texts: list[str] = []
        failures: list[str] = []

        LOGGER.info("Fetching %d upstream source(s)", len(sources))

        for index, source in enumerate(sources, start=1):
            LOGGER.info("Fetching source %d/%d: %s", index, len(sources), source.url)

            try:
                text = fetch_text(source.url, args.timeout)

                if not text.strip():
                    message = f"{source.url}: downloaded empty response"
                    failures.append(message)
                    LOGGER.warning(message)
                    continue

                texts.append(text)
                LOGGER.info("Fetched source %d/%d successfully: %s", index, len(sources), source.url)

            except Exception as exc:
                message = f"{source.url}: {exc}"
                failures.append(message)
                LOGGER.exception("Failed to fetch source %d/%d: %s", index, len(sources), source.url)

        if not texts:
            raise PiHoleError("No upstream sources could be read; refusing to replace blocklists.")

        if failures and args.fail_on_source_error:
            raise PiHoleError("One or more upstream sources failed:\n" + "\n".join(failures))

        LOGGER.info("De-duplicating blocklist entries from %d fetched source(s)", len(texts))
        domains = dedupe_entries_exact(texts)

        if not domains:
            raise PiHoleError("No entries found after de-duplication; refusing to replace blocklists.")

        LOGGER.info("Writing master list to %s", args.output)
        write_master_list(args.output, domains, sources)

        chunk_size_bytes = args.chunk_size_mb * 1024 * 1024
        LOGGER.info(
            "Splitting master list into chunks under %s with max chunk size %d byte(s)",
            args.chunk_dir,
            chunk_size_bytes,
        )
        chunks = split_master_list(args.output, args.chunk_dir, chunk_size_bytes)

        LOGGER.info("Build completed successfully")
        LOGGER.info("Read %d of %d source(s)", len(texts), len(sources))
        LOGGER.info("Wrote %d unique blocklist entrie(s) to %s", len(domains), args.output)
        LOGGER.info("Wrote %d chunk file(s) to %s", len(chunks), args.chunk_dir)

        if failures:
            LOGGER.warning("Completed with %d source failure(s)", len(failures))
            for failure in failures:
                LOGGER.warning("Source failure: %s", failure)

        return 0

    except PiHoleError:
        raise
    except KeyboardInterrupt as exc:
        raise PiHoleError("Interrupted by user") from exc
    except Exception as exc:
        LOGGER.error("Unexpected fatal error: %s", exc)
        LOGGER.debug("Traceback:\n%s", traceback.format_exc())
        raise PiHoleError(f"Unexpected fatal error: {exc}") from exc


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PiHoleError as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(1)
