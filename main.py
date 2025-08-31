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
        requests.exceptions.ChunkedEncodingError,
    ),
    max_tries=10,
    max_time=120,
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
            timeout=(30, 120),  # (connection timeout, read timeout)
            stream=False,  # Download all content at once
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.ChunkedEncodingError as e:
        logger.error(f"Chunked encoding error occurred: {e}")
        raise
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

    adguard_rules.sort()

    return adguard_rules


def convert_to_hosts_format(items: list) -> list:
    """
    Convert the list of URLs to hosts format for PiHole/AdGuard Home

    Args:
        items (list): List of URLs or domains to convert

    Returns:
        list: List of hosts formatted rules
    """
    hosts_rules = []
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

            # Convert to hosts format (0.0.0.0 domain)
            hosts_rule = f"0.0.0.0 {domain}"
            hosts_rules.append(hosts_rule)
        except Exception:
            logger.error(f"ERROR: Invalid record - {record}")
            continue

    # Sort rules alphabetically (A-Z) to ensure consistent ordering
    hosts_rules.sort()

    return hosts_rules


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


def save_hosts_list(rules: list, filename: str) -> None:
    """
    Save the hosts formatted rules to a file for PiHole/AdGuard Home

    Args:
        rules (list): List of hosts formatted rules
        filename (str): The name of the file to save the rules to

    Returns:
        None
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # Hosts file başlığı
            f.write("# Title: USOM Blacklist (Hosts Format)\n")
            f.write("#\n")
            f.write("# Description: This hosts file contains USOM malicious URL list converted to hosts format\n# for use with PiHole, AdGuard Home, and other DNS filtering solutions\n")
            f.write("#\n")
            f.write(f"# Date: {datetime.now().strftime('%d %B %Y %H:%M:%S')} (UTC)\n")
            f.write(f"# Number of unique domains: {len(rules):,}\n")
            f.write("#\n")
            f.write("# Fetch the latest version of this file: https://www.usom.gov.tr/url-list.txt\n")
            f.write("# Project home page: https://github.com/ramazansancar/mertcangokgoz_usom-adguard-mirror\n")
            f.write("#\n")
            f.write("# ===============================================================\n")
            f.write("\n")
            f.write("# Standart localhost entries\n")
            f.write("127.0.0.1 localhost\n")
            f.write("127.0.0.1 localhost.localdomain\n")
            f.write("127.0.0.1 local\n")
            f.write("255.255.255.255 broadcasthost\n")
            f.write("::1 localhost\n")
            f.write("::1 ip6-localhost\n")
            f.write("::1 ip6-loopback\n")
            f.write("fe80::1%lo0 localhost\n")
            f.write("ff00::0 ip6-localnet\n")
            f.write("ff00::0 ip6-mcastprefix\n")
            f.write("ff02::1 ip6-allnodes\n")
            f.write("ff02::2 ip6-allrouters\n")
            f.write("ff02::3 ip6-allhosts\n")
            f.write("0.0.0.0 0.0.0.0\n")
            f.write("\n")
            f.write("# Custom host records are listed here.\n")
            f.write("\n")
            f.write("# End of custom host records.\n")
            f.write("# Start USOM Blacklist\n")
            f.write("\n")
            f.write("#=====================================\n")
            f.write("# Title: USOM Zararlı URL Listesi\n")
            f.write("# Source: https://www.usom.gov.tr/url-list.txt\n")
            f.write("\n")

            # Kuralları yaz
            for rule in rules:
                f.write(rule + "\n")

        logger.info(f"Hosts list saved to {filename}")
        logger.info(f"Total domains: {len(rules)}")

    except Exception as e:
        logger.error(f"ERROR: Failed to save hosts list - {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Convert USOM URL list to AdGuard and Hosts formats"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="usom_adguard_blacklist.txt",
        help="AdGuard output file name (default: usom_adguard_blacklist.txt)",
    )
    parser.add_argument(
        "--hosts-output",
        default="usom_hosts_blacklist.txt",
        help="Hosts output file name (default: usom_hosts_blacklist.txt)",
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

    # Hosts formatına dönüştür
    logger.info("Converting URLs to Hosts format...")
    hosts_rules = convert_to_hosts_format(urls)

    if not hosts_rules:
        logger.error("No valid hosts rules to save.")
        return 1

    # Dosyalara kaydet
    save_adguard_list(adguard_rules, args.output)
    save_hosts_list(hosts_rules, args.hosts_output)

    return 0


if __name__ == "__main__":
    exit(main())
