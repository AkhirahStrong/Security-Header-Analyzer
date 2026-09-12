import requests

# Define the security headers to analyze
security_headers = {
    "Content-Security-Policy": {
        "explanation": "Controls which resources the browser can load.",
        "recommendation": (
            "Define a Content-Security-Policy that allows only the resources "
            "your application needs. Test the policy before enforcing it."
        ),
    },
    "Strict-Transport-Security": {
        "explanation": "Tells browsers to use HTTPS for future connections.",
        "recommendation": (
            "Enable HSTS after confirming the entire site works correctly "
            "over HTTPS."
        ),
    },
    "X-Content-Type-Options": {
        "explanation": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "X-Frame-Options": {
        "explanation": "Helps protect against clickjacking.",
        "recommendation": (
            "Set an appropriate X-Frame-Options policy, or use the CSP "
            "frame-ancestors directive to control framing."
        ),
    },
    "Referrer-Policy": {
        "explanation": "Controls how much referrer information is shared.",
        "recommendation": (
            "Define a Referrer-Policy appropriate for the site's privacy "
            "and application requirements."
        ),
    },
    "Permissions-Policy": {
        "explanation": "Controls access to selected browser features.",
        "recommendation": (
            "Define a Permissions-Policy that enables only the browser "
            "features and origins the application requires."
        ),
    },
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

        # Dictionary that will contain our analysis results
        analysis = {}

        # Counters
        score = 0
        missing_count = 0

        # Check each security header
        for header, details in security_headers.items():

            if header in headers:

                score += 1

                # Store the actual value returned by the website
                header_value = headers[header]

                # Default configuration rating for a present header
                configuration = "GOOD"

                # Perform basic value analysis for CSP
                if header == "Content-Security-Policy":

                    if "default-src" in header_value or "script-src" in header_value:
                        configuration = "GOOD"

                    else:
                        configuration = "LIMITED"

                # Store analysis for a present header
                analysis[header] = {
                    "status": "PRESENT",
                    "value": header_value,
                    "explanation": details["explanation"],
                    "recommendation": details["recommendation"],
                    "configuration": configuration,
                }

            else:

                missing_count += 1

                # Store analysis for a missing header
                analysis[header] = {
                    "status": "MISSING",
                    "value": None,
                    "explanation": details["explanation"],
                    "recommendation": details["recommendation"],
                    "configuration": None,
                }

        # Calculate the Security Header Score
        final_score = (score / len(security_headers)) * 100

        # Total number of security headers checked
        total_headers = len(security_headers)

        # Determine the overall security-header risk level
        if final_score >= 80:
            risk_level = "low"

        elif final_score >= 50:
            risk_level = "medium"

        else:
            risk_level = "high"

        # Terminal output for testing
        print(f"Security Header Risk: {risk_level.upper()}")
        print(f"Security Header Score: {final_score:.1f}%")

        # Build the final result returned to Flask
        results = {
            "url": request_url,
            "status_code": response.status_code,
            "headers": headers,
            "analysis": analysis,
            "score": final_score,
            "risk_level": risk_level,
            # Summary counts
            "summary": {
                "total": total_headers,
                "present": score,
                "missing": missing_count,
            },
        }

        return results

    except requests.RequestException as error:

        return {
            "url": request_url,
            "error": str(error),
        }
