#!/var/ossec/framework/python/bin/python3
import sys
import json
import urllib.request
import urllib.error

def send_case(alert, api_key, url):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})

    title = 'Wazuh Alert: ' + rule.get('description', 'Unknown')
    description = 'Agent: ' + agent.get('name', 'Unknown') + '\nRule: ' + str(rule.get('id', '')) + ' Level ' + str(rule.get('level', '')) + '\nLog: ' + alert.get('full_log', 'N/A')

    case = {
        'title': title,
        'description': description,
        'severity': 2 if int(rule.get('level', 0)) >= 12 else 1,
        'tags': ['wazuh', 'rule-' + str(rule.get('id', '')), agent.get('name', 'unknown')],
        'flag': False
    }

    req = urllib.request.Request(
        url + '/api/v1/case',
        data=json.dumps(case).encode('utf-8'),
        headers={
            'Authorization': 'Bearer ' + api_key,
            'Content-Type': 'application/json'
        },
        method='POST'
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print('Case created: ' + str(resp.status))
    except urllib.error.HTTPError as e:
        print('Error: ' + str(e.code) + ' ' + str(e.read()))

def main():
    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    url = sys.argv[3]

    with open(alert_file) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alert = json.loads(line)
                    send_case(alert, api_key, url)
                    break
                except json.JSONDecodeError:
                    pass

main()
