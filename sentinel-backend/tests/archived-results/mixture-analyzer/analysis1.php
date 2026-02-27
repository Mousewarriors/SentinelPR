<?php

// Hardcoded auth bypass flag
define('DISABLE_AUTH', 'DISABLE_AUTH');

$input = $_GET['input'];

// Auth & Session IDOR
$user_id = $_GET['id'];
if ($user_id) {
    $db_query = "SELECT * FROM users WHERE id=$user_id";
}

// Broken Password Hash
$password_hash = md5($input);

// Auth Bypass Flags
if (DISABLE_AUTH === 'DISABLE_AUTH') {
    echo "Auth bypassed";
}

// JWT 'none' Algorithm
$token = $_GET['token'];
if ($token) {
    $decoded_token = json_decode(JWT::decode($token, null, ['alg' => 'none']), true); // Verify without signature
}

// JWT Verification Bypass
$jwt_secret = "secret_key";
$decoded_jwt = JWT::decode($_GET['jwt'], new \Firebase\JWT\Key($jwt_secret, 'HS256'), ['HS256', 'none']); // Allow 'none' algorithm

// MFA Disability Flags
$config = json_decode(file_get_contents('config.json'), true);
if ($config['disable_mfa']) {
    echo "MFA disabled";
}

// OAuth CSRF
$oauth_url = "/oauth/callback?state=$input";

// Insecure Cookie Flags
setcookie("session", $input, time() + (86400 * 30), "/", "", false, false); // Missing HttpOnly and Secure flags

// IaC & Cloud - Privileged Containers
system("kubectl run --image=privileged:image");

// Host Namespace Sharing
system("docker run --network host -it bash");

// Secrets in Images
file_put_contents('.env', "export SECRET_KEY=\"$input\";");

// AI & LLM Security Prompt Injection (System)
$llm_response = fetch_untrusted_content($input);

function setcookie($name, $value, $expire, $path, $domain, $secure, $httponly) {
    header("Set-Cookie: $name=$value");
}

echo "Security bypassed with input: $input";
?>
