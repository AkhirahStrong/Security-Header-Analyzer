import requests

security_headers = {
    "Content-Security-Policy": "Controls which resources the browser can load.",
    "Strict-Transport-Security": "Forces the browser to use HTTPS.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Controls access to browser features.",
}


def scan_headers(request_url):

    if not request_url.startswith("http://") and not request_url.startswith("https://"):
        request_url = "https://" + request_url

    try:
        response = requests.get(request_url, timeout=10)

        headers = dict(response.headers)

        analysis = {}

        for header, explanation in security_headers.items():

            if header in headers:
                analysis[header] = {
                    "status": "PRESENT",
                    "value": headers[header],
                    "explanation": explanation,
                }

            else:
                analysis[header] = {
                    "status": "MISSING",
                    "value": None,
                    "explanation": explanation,
                }

        results = {
            "url": request_url,
            "status_code": response.status_code,
            "headers": headers,
            "analysis": analysis,
        }

        return results

    except requests.RequestException as error:

        return {"url": request_url, "error": str(error)}
