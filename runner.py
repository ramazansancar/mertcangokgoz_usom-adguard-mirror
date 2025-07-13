import asyncio
import aiohttp
import aiofiles
import argparse
from datetime import datetime
import logging

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")


async def download_url_list(url: str) -> str:
    """
    Download the USOM URL list from the given URL

    Args:
        url (str): The URL to download the list from

    Returns:
        str: The content of the URL list as a string, or None if an error occurs
    """
    try:
        print(f"Downloading: {url}")
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                content = await response.text(encoding="utf-8")
                return content
    except aiohttp.ClientError as e:
        print(f"ERROR: Download failed - {e}")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred - {e}")
        return None


async def convert_to_adguard_format(items: list) -> list:
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
            adguard_rule = f"||{domain}"
            adguard_rules.append(adguard_rule)
        except Exception:
            print(f"ERROR: Invalid record - {record}")
            continue

    return adguard_rules


async def save_adguard_list(rules: list, filename: str) -> None:
    """
    Save the AdGuard formatted rules to a file

    Args:
        rules (list): List of AdGuard formatted rules
        filename (str): The name of the file to save the rules to

    Returns:
        None
    """
    try:
        async with aiofiles.open(filename, "w", encoding="utf-8") as f:
            # AdGuard filter başlığı
            await f.write("! Title: USOM Blacklist (AdGuard Format)\n")
            await f.write(
                "! Description: USOM zararlı URL listesinin AdGuard formatına dönüştürülmüş halini içerir\n"
            )
            await f.write(
                f"! Last Modified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            await f.write(f"! Total Rules: {len(rules)}\n")
            await f.write("! Homepage: https://www.usom.gov.tr/\n")
            await f.write("!\n")

            # Kuralları yaz
            for rule in rules:
                await f.write(rule + "\n")

        print(f"AdGuard blacklist successfully saved: {filename}")
        print(f"Total number of rules: {len(rules)}")

    except Exception as e:
        print(f"ERROR: File could not be saved - {e}")


async def main():
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

    content = await download_url_list(args.url)
    if not content:
        return 1

    urls = content.split("\n")

    if args.verbose:
        print(f"Total number of lines: {len(urls)}")

    # AdGuard formatına dönüştür
    print("Converting to AdGuard format...")
    adguard_rules = await convert_to_adguard_format(urls)

    if not adguard_rules:
        print("ERROR: No valid record found")
        return 1

    # Dosyaya kaydet
    await save_adguard_list(adguard_rules, args.output)

    return 0


if __name__ == "__main__":
    exit(asyncio.run(main()))
