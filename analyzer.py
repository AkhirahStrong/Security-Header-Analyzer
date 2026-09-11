import requests

# Define the security headers to analyze
security_headers = {
    "Content-Security-Policy": "Controls which resources the browser can load.",
    "Strict-Transport-Security": "Forces the browser to use HTTPS.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Controls access to browser features.",
}


def scan_headers(request_url):
    # Ensure the URL starts with http:// or https://
    if not request_url.startswith("http://") and not request_url.startswith("https://"):
        request_url = "https://" + request_url

    try:
        # Make a GET request to the provided URL with a timeout
        response = requests.get(request_url, timeout=10)

        # Extract the headers from the response
        headers = dict(response.headers)

        # Analyze the headers against the defined security headers (security_headers{})
        analysis = {}

        score = 0

        for header, explanation in security_headers.items():

            if header in headers:
                score += 1

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

        final_score = (score / len(security_headers)) * 100

        if final_score >= 80:
            print("You have a low risk score.")
        elif final_score >= 50:
            print("You have a medium risk score.")
        else:
            print("You have a high risk score.")

        print(f"Your security score is: {final_score:.1f}%")

        results = {
            "url": request_url,
            "status_code": response.status_code,
            "headers": headers,
            "analysis": analysis,
            "score": final_score,
            "risk_level": (
                "low"
                if final_score >= 80
                else "medium" if final_score >= 50 else "high"
            ),
        }

        return results

    except requests.RequestException as error:

        return {"url": request_url, "error": str(error)}
