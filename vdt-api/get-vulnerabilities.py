import requests
import argparse
import json
import csv
import urllib3

HEADERS={}
VERIFY=False

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_token():
    # Get Wazuh JWT token
    request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY)

    if request_result.status_code == 200:
       TOKEN = json.loads(request_result.content.decode())['data']['token']
       HEADERS['Authorization'] = f'Bearer {TOKEN}'
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

def get_agents_in_group(group):
    # Get active agents by searching for Centos
    agents_ids = []
    limit = 500
    offset = 0
    finish = False

    while not finish:
        agents_request = requests.get(WAZUH_API + f"/groups/{group}/agents?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if agents_request.status_code == 200:
            agents_list = json.loads(agents_request.content.decode())['data']

            for agent in agents_list['affected_items']:
                agents_ids.append(agent)
            
            # If there are more items to be gathered, iterate the offset
            if agents_list['total_affected_items'] > (limit + offset):
                offset = offset + limit

                if (offset + limit) > agents_list['total_affected_items']:
                    limit = agents_list['total_affected_items'] - offset

            else:
                finish = True
        else:
            if agents_request.status_code == 401:
                # Renew token
                get_token()
            else:
                raise Exception(f"Error obtaining response: {agents_request.json()}")

    return agents_ids

def get_vulnerabilities(agent):
    # Get vulnerabilities info from agent
    limit = 500
    offset = 0
    finish = False
    agent_vulnerabilities = []

    while not finish:
        vulnerabilities_request = requests.get(WAZUH_API + f"/vulnerability/{agent['id']}?limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if vulnerabilities_request.status_code == 200:
            vulnerabilities_result = json.loads(vulnerabilities_request.content.decode())['data']

            for result in vulnerabilities_result['affected_items']:
                # Exclude duplicated package names as a package can have multiple CVEs
                if result['name'] not in agent_vulnerabilities:
                    agent_vulnerabilities.append(result['name'])

            # If there are more items to be gathered, iterate the offset
            if vulnerabilities_result['total_affected_items'] > (limit + offset):
                offset = offset + limit
                
                if (offset + limit) > vulnerabilities_result['total_affected_items']:
                    limit = vulnerabilities_result['total_affected_items'] - offset
            else:
                finish = True
        else:
            if vulnerabilities_request.status_code == 401:
                # Renew token
                get_token()
            else:
                raise Exception(f"Error obtaining response: {vulnerabilities_request.json()}")

    return agent_vulnerabilities

def main():

    get_token()

    for group in AGENT_GROUPS:
        agents = get_agents_in_group(group)

        print(f"Vulnerability report for group {group}")
        for agent in agents:
            vulnerabilities = get_vulnerabilities(agent)

            if not vulnerabilities:
                continue

            print(f"Vulnerabilities for agent: {agent['id']} - {agent['name']} \nPackage names: {vulnerabilities}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default='127.0.0.1', help='Wazuh API server IP.')
    parser.add_argument('-u', '--user', type=str, default='wazuh', help='Wazuh API user.')
    parser.add_argument('-p', '--password', type=str, default='wazuh', help='Wazuh API password.')
    parser.add_argument('-g', '--groups', type=str, default='default', help='Comma separated list of groups')
    args = parser.parse_args()

    WAZUH_IP = args.server
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    AGENT_GROUPS = args.groups.split(",")

    WAZUH_API=f"https://{WAZUH_IP}:55000"

    main()