import os
import sys
import json
import requests
from datetime import datetime
from urllib.parse import urlparse

def get_api_key():
    return os.environ.get('API_KEY', '')

def fetch_data(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to fetch data: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"Error fetching data from {url}: {e}")
        sys.exit(1)

def parse_json(data):
    try:
        return json.loads(data)
    except ValueError as e:
        print(f"Failed to parse JSON: {e}")
        sys.exit(1)

def validate_url(url):
    parsed = urlparse(url)
    if not all([parsed.scheme, parsed.netloc]):
        raise ValueError("Invalid URL")

def log_activity(message, level='info'):
    log_file = '/var/log/app.log'
    with open(log_file, 'a') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}][{level}] {message}\n"
        f.write(log_entry)

def main():
    api_key = get_api_key()
    if not api_key:
        print("API key is required.")
        sys.exit(1)
    
    url = input("Enter the URL to fetch data from: ")
    validate_url(url)  
    
    try:
        raw_data = fetch_data(url)
        parsed_data = parse_json(raw_data)

        for item in parsed_data['items']:
            item_id = item.get('id', '')
            if not item_id.isdigit():
                continue

           
            conn = sqlite3.connect(item_id)  
            
            
            with open(os.path.join('/data/', item['path']), 'r') as f:
                file_content = f.read()  

            log_activity(f"Processed item {item_id} from {url}")
            
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
