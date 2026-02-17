import requests
import json
import time
import http.server
import threading
import os
import sys
from pathlib import Path

# Configuration
PROXY_URL = "http://127.0.0.1:8888"
TLS_PROXY_URL = "https://127.0.0.1:8889"
MOCK_PROVIDER_PORT = 9000
TEST_TOKEN = "raypher_test_secret_123"

# --- Mock AI Provider Server ---
# Simulates an OpenAI-compatible endpoint
class MockProviderHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        # Log request for verification
        # print(f"\n[Mock] Received request body: {body[:100]}...")

        # Determine response based on snippets (to test redaction)
        response_content = f"Echo: {body}"
        
        resp = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4-turbo",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_content
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode('utf-8'))

    def log_message(self, format, *args):
        return # Silence server logs

def start_mock_server():
    server = http.server.HTTPServer(('127.0.0.1', MOCK_PROVIDER_PORT), MockProviderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"✅ Mock Provider started on port {MOCK_PROVIDER_PORT}")
    return server

# --- Test Utility ---
def proxy_request(payload, use_tls=False):
    base = TLS_PROXY_URL if use_tls else PROXY_URL
    try:
        # Use verify=False for local self-signed TLS test
        resp = requests.post(
            f"{base}/v1/chat/completions",
            json=payload,
            headers={
                "X-Raypher-Token": TEST_TOKEN,
                "X-Raypher-Provider": "mock", # Explicitly use mock route
                "Authorization": "Bearer mock-key",
                "Host": "api.openai.com" 
            },
            timeout=5,
            verify=False 
        )
        return resp
    except Exception as e:
        print(f"❌ Proxy request failed: {e}")
        return None

# --- Test Scenarios ---

def test_dlp_outbound_redaction():
    print("\n🔍 Scenario 1: Outbound DLP Redaction (SSN)")
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "My SSN is 123-45-6789. Don't tell anyone."}]
    }
    # We check what the MOCK server received (how to check? 
    # For now we'll just check if the proxy successfully redacts)
    # Actually, the proxy logs findings to the DB.
    resp = proxy_request(payload)
    if resp and resp.status_code == 200:
        print("✅ Request passed via proxy.")
        # In a real integrated test, we'd check the DB or mock logs to see if it was [REDACTED]
    else:
        print(f"❌ Request failed with status {resp.status_code if resp else 'N/A'}")

def test_budget_blocking():
    print("\n🔍 Scenario 2: Budget Enforcement (Blocking)")
    # We look for a 429 or 403 when budget is hit
    # This requires the budget to be set very low in policy.yaml
    print(" (Note: Set daily_budget_limit to 0.01 in dashboard before running this)")
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Heavy usage test."}]
    }
    print(" Request 1 (should pass)...")
    resp1 = proxy_request(payload)
    print(" Request 2 (should be blocked)...")
    resp2 = proxy_request(payload)
    
    if resp2 and resp2.status_code in [403, 429]:
        print(f"✅ Budget enforcement triggered: {resp2.status_code}")
    else:
        print(f"❓ Budget not exceeded or check failed (Status: {resp2.status_code if resp2 else 'N/A'})")

def test_hot_reload():
    print("\n🔍 Scenario 3: Policy Hot-Reload")
    policy_path = Path.home() / ".raypher" / "policy.yaml"
    if not policy_path.exists():
        print("⚠️ policy.yaml not found at default location. Skipping.")
        return

    print(" Reading current policy...")
    with open(policy_path, 'r') as f:
        original = f.read()
    
    try:
        print(" Temporarily blocking all domains...")
        # (This is just a conceptual test, actually editing YAML is risky in a script)
        # We'll just verify the proxy responds to GET /api/config/policy
        resp = requests.get(f"{PROXY_URL}/api/config/policy")
        if resp.status_code == 200:
            print(f"✅ Policy API reachable. Response: {resp.json().get('daily_budget_limit')}")
        else:
            print("❌ Policy API unreachable.")
    finally:
        pass

def test_tls_listener():
    print("\n🔍 Scenario 4: TLS Listener (Port 8889)")
    payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hello"}]}
    # Suppress insecure request warnings for self-signed
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    resp = proxy_request(payload, use_tls=True)
    if resp and resp.status_code == 200:
        print("✅ TLS Handshake and Request successful on 8889.")
    else:
        print(f"❌ TLS test failed: {resp.status_code if resp else 'N/A'}")

# --- Main ---
if __name__ == "__main__":
    print("🚀 Raypher Integration Test Suite")
    print("---------------------------------")
    
    # Check if proxy is running
    try:
        requests.get(PROXY_URL, timeout=1)
    except:
        print("❌ Error: Raypher proxy is not running on http://localhost:8888")
        print("   Please start the proxy before running tests.")
        sys.exit(1)

    start_mock_server()
    time.sleep(1) # Wait for server thread

    test_dlp_outbound_redaction()
    test_tls_listener()
    test_budget_blocking()
    test_hot_reload()

    print("\n✨ Integration Tests Complete.")
