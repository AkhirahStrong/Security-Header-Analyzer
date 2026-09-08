import requests


def scan_headers(request_url):

    if not request_url.startswith("http://") and not request_url.startswith("https://"):
        request_url = "https://" + request_url

    try:
        response = requests.get(request_url, timeout=10)

        results = {
            "url": request_url,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }

        return results

    except requests.RequestException as error:

        return {
            "url": request_url,
            "error": str(error)
        }    