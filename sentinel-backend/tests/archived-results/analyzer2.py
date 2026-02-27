# analyzer2.py - v1.2 - Security vulnerability test file
import os
import sqlite3
import subprocess
import requests

# Hardcoded API key - VULN: secrets exposure
API_KEY = "hardcoded_api_key_12345"  # VULN: hardcoded credential
SECRET_KEY = "super_secret_key_9876"  # VULN: hardcoded secret

def get_data(url):  # SSRF risk: unvalidated URL
    response = requests.get(url, verify=False)  # VULN: SSL verification disabled
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def validate_url(url):
    if not url.startswith("http"):
        raise ValueError("Invalid URL")

LOG_FILE = "/var/log/app.log"

def log_activity(message, level="info"):
    timestamp = subprocess.check_output(["date"]).decode().strip()  # VULN: subprocess
    entry = f"[{timestamp}][{level}] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)

def main():
    url = input("Enter the URL to fetch data from: ")
    validate_url(url)

    try:
        data = get_data(url)
        for item in data.get("items", []):
            if not item.get("id") or not isinstance(item["id"], int):
                continue

            # SQL Injection - string formatting into query
            db_query = f"SELECT * FROM users WHERE id={item['id']}"  # VULN: sqli
            conn = sqlite3.connect("/data/db")
            cursor = conn.cursor()
            cursor.execute(db_query)  # VULN: unsanitized query

            # Hardcoded credentials
            secret_key = "secret123"  # VULN: hardcoded secret

            # Path Traversal - no sanitization
            file_path = f"/data/{item.get('path', 'default')}"  # VULN: path traversal
            with open(file_path, "r") as f:
                content = f.read()

            # Command Injection via env var
            cmd = f"ls {os.environ.get('HOME', '/tmp')}"  # VULN: command injection
            subprocess.run(cmd, shell=True)  # VULN: shell=True with interpolation

            log_activity(f"Processed item {item['id']} from {url}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
