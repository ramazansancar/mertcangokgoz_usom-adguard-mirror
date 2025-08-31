import os

HEADERS: dict = {
    "User-Agent": "Mozilla/5.0 (compatible; USOM-LIST-ADGUARD-FORMATTER; https://github.com/mertcangokgoz/usom-adguard-mirror)",
    "Accept": "text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
}

PROXY: dict = {
    "http": os.getenv("PROXY"),
    "https": os.getenv("PROXY"),
}
