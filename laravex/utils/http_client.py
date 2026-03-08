import requests
from urllib.parse import urlparse

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Laravex/1.0 (Laravel Penetration Testing Tool)"
        })

    def get(self, url, **kwargs):
        return self.session.get(url, **kwargs)

    def close(self):
        self.session.close()

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"

http_client = HTTPClient()
