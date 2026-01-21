import os
import json
import requests
import datetime
import hashlib
import hmac
import base64

def send_log_to_loganalytics(log_type, log_data):
    workspace_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID', '').strip()
    shared_key = os.environ.get('LOG_ANALYTICS_SHARED_KEY', '').strip()

    if not workspace_id or not shared_key:
        print("❌ Missing LOG_ANALYTICS_WORKSPACE_ID or LOG_ANALYTICS_SHARED_KEY.")
        return

    body = json.dumps(log_data)
    content_bytes = body.encode('utf-8')
    content_length = len(content_bytes)

    timestamp = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    string_to_hash = (
        f"POST\n"
        f"{content_length}\n"
        f"application/json\n"
        f"x-ms-date:{timestamp}\n"
        f"/api/logs"
    )

    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode('utf-8'), hashlib.sha256).digest()
    ).decode()

    uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    print("Workspace ID:", workspace_id)
    print("Log Analytics URL:", uri)

    headers = {
        "Content-Type": "application/json",
        "Log-Type": log_type,
        "x-ms-date": timestamp,
        "Authorization": f"SharedKey {workspace_id}:{encoded_hash}"
    }

    print(f"Sending to Log Analytics: {len(log_data)} entries")
    print(f"POST {uri}")

    try:
        response = requests.post(uri, json=log_data, headers=headers, timeout=10)
    except Exception as e:
        print("❌ Exception while sending logs:", e)
        return

    print(f"Response: {response.status_code} - {response.text}")

    if response.status_code not in (200, 202):
        print(f"❌ Failed to send logs: {response.status_code} - {response.text}")
    else:
        print("✅ Logs sent to Log Analytics.")

    return response