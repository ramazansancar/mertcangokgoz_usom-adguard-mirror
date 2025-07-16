import requests
import backoff
import argparse
from datetime import datetime
from constant import HEADERS, PROXY
import logging
import os

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")


@backoff.on_exception(
    backoff.expo,
    (
        requests.exceptions.Timeout,
        requests.exceptions.ReadTimeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
        requests.exceptions.HTTPError,
    ),
    max_tries=6,
    max_time=60,
)
def download_url_list(url: str) -> str:
    """
    Download the USOM URL list from the given URL

    Args:
        url (str): The URL to download the list from

    Returns:
        str: The content of the URL list as a string, or None if an error occurs
    """
    try:
        print(f"Downloading: {url}")
        response = requests.get(
            url,
            headers=HEADERS,
            proxies=PROXY if os.getenv("PROXY") else None,
            allow_redirects=True,
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred: {e}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Error occurred while downloading the URL list: {e}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return None


def convert_to_adguard_format(items: list) -> list:
    """
    Convert the list of URLs to AdGuard format

    Args:
        items (list): List of URLs or domains to convert

    Returns:
        list: List of AdGuard formatted rules
    """
    adguard_rules = []
    processed_domains = set()

    for item in items:
        record = item.strip()

        if not record or record.startswith("#"):
            continue

        try:
            domain = record.lower().strip()

            # Duplicate Check
            if domain in processed_domains:
                continue

            processed_domains.add(domain)

            # Convert to AdGuard format
            adguard_rule = f"||{domain}^"
            adguard_rules.append(adguard_rule)
        except Exception:
            logger.error(f"ERROR: Invalid record - {record}")
            continue

    return adguard_rules


def save_adguard_list(rules: list, filename: str) -> None:
    """
    Save the AdGuard formatted rules to a file

    Args:
        rules (list): List of AdGuard formatted rules
        filename (str): The name of the file to save the rules to

    Returns:
        None
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # AdGuard filter başlığı
            f.write("! Title: USOM Blacklist (AdGuard Format)\n")
            f.write(
                "! Description: USOM zararlı URL listesinin AdGuard formatına dönüştürülmüş halini içerir\n"
            )
            f.write(
                f"! Last Modified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"! Total Rules: {len(rules)}\n")
            f.write("! Homepage: https://www.usom.gov.tr/url-list.txt\n")
            f.write("!\n")

            # Kuralları yaz
            for rule in rules:
                f.write(rule + "\n")

        logger.info(f"AdGuard list saved to {filename}")
        logger.info(f"Total rules: {len(rules)}")

    except Exception as e:
        logger.error(f"ERROR: Failed to save AdGuard list - {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Convert USOM URL list to AdGuard format"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="usom_adguard_blacklist.txt",
        help="Output file name (default: usom_adguard_blacklist.txt)",
    )
    parser.add_argument(
        "-u",
        "--url",
        default="https://www.usom.gov.tr/url-list.txt",
        help="URL list to download (default: https://www.usom.gov.tr/url-list.txt)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Detailed output")

    args = parser.parse_args()

    content = download_url_list(args.url)
    if not content:
        return 1

    urls = content.split("\n")

    if args.verbose:
        logger.info(f"Total URLs downloaded: {len(urls)}")

    # AdGuard formatına dönüştür
    logger.info("Converting URLs to AdGuard format...")
    adguard_rules = convert_to_adguard_format(urls)

    if not adguard_rules:
        logger.error("No valid rules to save.")
        return 1

    # Dosyaya kaydet
    save_adguard_list(adguard_rules, args.output)

    return 0


if __name__ == "__main__":
    exit(main())
