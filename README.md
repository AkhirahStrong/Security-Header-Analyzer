# Security Header Analyzer

A Python web application that analyzes HTTP response headers to help identify missing security protections on websites.

The tool accepts a website URL, sends an HTTP request, retrieves the response headers, and displays the results through a simple web interface.

## Purpose

HTTP security headers can help protect web applications against common browser-based attacks and security risks.

This project was created to practice Python, HTTP communication, and web security concepts while building a practical cybersecurity tool.

## Current Features

- Accepts a website URL
- Automatically adds HTTPS when a protocol is not provided
- Sends HTTP requests using Python Requests
- Retrieves HTTP response headers
- Displays HTTP status codes
- Displays response headers
- Handles request errors and timeouts
- Flask-based web interface

## Security Headers

The analyzer is being developed to evaluate headers including:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

## Planned V1 Features

- Detect present and missing security headers
- Explain the purpose of each security header
- Calculate a security score
- Assign a basic risk level
- Improve result presentation

## Tech Stack

- Python
- Flask
- Requests
- HTML
- CSS

## Project Structure

```text
security-header-analyzer/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```
