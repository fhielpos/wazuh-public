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

def get_active_agents():
    # Get active agents by searching for Centos
    agents_ids = []
    limit = 500
    offset = 0
    finish = False

    while not finish:
        agents_request = requests.get(WAZUH_API + f"/agents?status=active&select=id,name&limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if agents_request.status_code == 200:
            agents_list = json.loads(agents_request.content.decode())['data']

            for agent in agents_list['affected_items']:
                agents_ids.append(agent)
            
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

def get_syscheck_agent(agent):
    # Get syscheck info from agent
    limit = 500
    offset = 0
    finish = False
    syscheck_files = []

    while not finish:
        syscheck_request = requests.get(WAZUH_API + f"/syscheck/{agent['id']}?type=file&select=file,inode,uname,gname,perm&search=/etc/&limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if syscheck_request.status_code == 200:
            syscheck_result = json.loads(syscheck_request.content.decode())['data']

            for result in syscheck_result['affected_items']:
                syscheck_files.append(result)

            if syscheck_result['total_affected_items'] > (limit + offset):
                offset = offset + limit
                
                if (offset + limit) > syscheck_result['total_affected_items']:
                    limit = syscheck_result['total_affected_items'] - offset
            else:
                finish = True
        else:
            if syscheck_request.status_code == 401:
                # Renew token
                get_token()
            else:
                raise Exception(f"Error obtaining response: {syscheck_request.json()}")

    return syscheck_files

def main():
    # Write header to csv file
    csv_header = ["agent.id","agent.name","file.perm","file.inode","file.uname","file.gname","file.name"]

    with open(CSV_PATH, "w", encoding='UTF8', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_header)

    get_token()
    agents = get_active_agents()
    
    for agent in agents:
        files = get_syscheck_agent(agent)

        if not files:
            continue

        for file in files:
            csv_data = [agent['id'],agent['name'],file['perm'],file['inode'],file['uname'],file['gname'],file['file']]

            with open(CSV_PATH, "a", encoding='UTF8', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(csv_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', type=str, default='output.csv', help='Output path of the CSV file.')
    parser.add_argument('-s', '--server', type=str, required='true', help='Wazuh API server IP.')
    parser.add_argument('-u', '--user', type=str, default='wazuh', help='Wazuh API user.')
    parser.add_argument('-p', '--password', type=str, default='wazuh', help='Wazuh API password.')
    args = parser.parse_args()

    CSV_PATH = args.output
    WAZUH_IP = args.server
    WAZUH_USER = args.user
    WAZUH_PASS = args.password
    WAZUH_API=f"https://{WAZUH_IP}:55000"

    main()