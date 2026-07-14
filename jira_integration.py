import requests
from requests.auth import HTTPBasicAuth

def create_jira_issue(jira_url, username, api_token, project_key, summary, description):
    url = f"{jira_url}/rest/api/2/issue"
    auth = HTTPBasicAuth(username, api_token)
    headers = {"Content-Type": "application/json"}
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"}
        }
    }
    try:
        resp = requests.post(url, json=payload, auth=auth, headers=headers, timeout=10)
        return resp.status_code == 201
    except:
        return False
