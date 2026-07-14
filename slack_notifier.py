import requests
import json

def send_slack_notification(webhook_url, results, target):
    if not webhook_url:
        return
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for r in results:
        sev = r.get('severity', 'low').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    text = f"🛡️ *API Security Scan Complete*\n"
    text += f"• Target: {target}\n"
    text += f"• Total vulnerabilities: {len(results)}\n"
    text += f"• Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}, Low: {severity_counts['low']}"
    payload = {"text": text}
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except:
        pass
