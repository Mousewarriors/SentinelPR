import os
from jinja2 import Template
import subprocess
import pickle
import requests
import json
from flask import Flask, request


app = Flask(__name__)

@app.route('/<input_str>')
def handle_request(input_str):
    # SQL Injection
    db_query = f"SELECT * FROM users WHERE id={input_str}"

    # Unsafe Raw SQL APIs
    raw_query = f"queryRawUnsafe({input_str})"

    # NoSQL Operator Injection
    mongo_query = { "$where": input_str }

    # Command Injection (RCE)
    subprocess.run(['ls', '/home/' + input_str], check=True)

    # Remote Code Execution
    eval(input_str)

    # Template Injection (SSTI)
    template = "{{% if " + input_str + " %}}Admin{% endif %}"
    
    # LDAP Injection
    ldap_filter = f"(&(objectClass=user)(sAMAccountName={input_str}))"

    # XML External Entity (XXE)
    xml_data = "<note><to>" + input_str + "</to></note>"

    # Zip Slip Path Traversal
    with open(f"./{input_str}", 'r') as file:
        pass

    # Unsafe Deserialization
    deserialized_data = pickle.loads(input_str)

    # Auth & Session IDOR
    user_query = f"SELECT * FROM users WHERE id={input_str}"

    # Broken Password Hash
    hash_password = input_str.lower().replace('.', '')

    # Auth Bypass Flags
    if DISABLE_AUTH == 'DISABLE_AUTH':
        print('Auth bypassed')

    # JWT 'none' Algorithm
    token = f"eyJhbGciOiJub25lIn0.{input_str}.signature"

    # JWT Verification Bypass
    decoded_jwt = json.loads(token.split('.')[1])

    # MFA Disability Flags
    if config['disable_mfa']:
        print('MFA disabled')

    # OAuth CSRF
    oauth_url = f"/oauth/callback?state={input_str}"

    # Insecure Cookie Flags
    response.headers.add('Set-Cookie', f"session={input_str}; HttpOnly=false")

    # IaC & Cloud - Privileged Containers
    subprocess.run(['kubectl', 'run', '--image=privileged:image'], check=True)

    # Host Namespace Sharing
    subprocess.run(['docker', 'run', '--network', 'host', '-it', 'bash'], check=True)

    # Secrets in Images
    with open('.env', 'w') as file:
        file.write(f"export SECRET_KEY=\"{input_str}\";\n")

    # AI & LLM Security Prompt Injection (System)
    prompt = f"Generate a response for {input_str}"

    # Tool Injection
    subprocess.run([input_str], check=True)

    # Unmoderated AI Context
    response = requests.get(f"https://api.ai/{input_str}")
    print(response.text)

    return f'Security bypassed with input: {input_str}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
