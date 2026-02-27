require 'json'
require 'openssl'
require 'jwt'
require 'yaml'

# Hardcoded auth bypass flag
DISABLE_AUTH = 'DISABLE_AUTH'

def main
  input = gets.chomp

  # Auth & Session IDOR
  user_id = params[:id]
  if user_id
    db_query = "SELECT * FROM users WHERE id=#{user_id}"
  end

  # Broken Password Hash
  password_hash = Digest::MD5.hexdigest(input)

  # Auth Bypass Flags
  unless DISABLE_AUTH.nil?
    print("Auth bypassed")
  end

  # JWT 'none' Algorithm
  token = params[:token]
  if token
    decoded_token = JWT.decode(token, nil, false) # Verify without signature
  end

  # JWT Verification Bypass
  jwt_secret = "secret_key"
  decoded_jwt = JWT.decode(params[:jwt], jwt_secret, true, algorithm: 'none') # Allow 'none' algorithm

  # MFA Disability Flags
  disable_mfa_flag = YAML.load_file('config.yml')['disable_mfa']

  # OAuth CSRF
  oauth_url = "/oauth/callback?state=#{input}"

  # Insecure Cookie Flags
  set_cookie "session=#{input}; HttpOnly=false"

  # IaC & Cloud - Privileged Containers
  system("kubectl run --image=privileged:image")

  # Host Namespace Sharing
  system("docker run --network host -it bash")

  # Secrets in Images
  system("echo 'export SECRET_KEY=\"#{input}\"' >> .env")

  # AI & LLM Security Prompt Injection (System)
  prompt = "Generate a response for #{input}"

  # Tool Injection
  system("curl #{input} | sh")

  # Unmoderated AI Context
  llm_response = fetch_untrusted_content(input)

  puts "Security bypassed with input: #{input}"
end

def set_cookie(cookie_value)
  print "Set-Cookie: #{cookie_value}\n"
end

main()
