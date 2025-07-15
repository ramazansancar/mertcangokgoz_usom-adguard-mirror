import os

HEADERS: dict = {
    "User-Agent": "Mozilla/5.0 (compatible; USOM-LIST-ADGUARD-FORMATTER; https://github.com/mertcangokgoz/usom-adguard-mirror)",
    "Connection": "keep-alive",
    "Accept": "*/*",
}

PROXY: dict = {
    "http": os.getenv("PROXY"),
    "https": os.getenv("PROXY"),
}
