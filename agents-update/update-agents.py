import requests
import argparse
import json
import urllib3
import warnings

HEADERS={}
VERIFY=False

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter("ignore")

def get_token():
    # Get Wazuh JWT token
    request_result = requests.get(WAZUH_API + "/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY)

    if request_result.status_code == 200:
       TOKEN = json.loads(request_result.content.decode())['data']['token']
       HEADERS['Authorization'] = f'Bearer {TOKEN}'
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

def get_outdated():
    # Get outdated agents that are active
    agents_ids = []
    limit = 10000
    offset = 0
    finish = False

    while not finish:
        agents_request = requests.get(WAZUH_API + f"/agents/outdated?q=status=active&limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

        if agents_request.status_code == 200:
            agent_list = json.loads(agents_request.content.decode())['data']

            for agent in agent_list['affected_items']:
                agents_ids.append(agent['id'])
            
            # If there are more items to be gathered, iterate the offset
            if agent_list['total_affected_items'] > (limit + offset):
                offset = offset + limit

                if (offset + limit) > agent_list['total_affected_items']:
                    limit = agent_list['total_affected_items'] - offset

            else:
                finish = True
        else:
            if agents_request.status_code == 401:
                # Renew token
                get_token()
            else:
                raise Exception(f"Error obtaining response: {agents_request.json()}")

    return agents_ids

def update_agents(agent_list):
    # Update agent list
    
    offset = 0
    batch = 100
    if len(agent_list) < batch:
        limit = len(agent_list)
    else:
        limit = batch
    finish = False
    
    while not finish:
        if len(agent_list[offset:limit]) > batch:            
            raise Exception(f"Error: We can only update {batch} agents at a time")
        elif len(agent_list[offset:limit]) < 1:
            raise Exception(f"Error: There should be at least one agent to update")

        agents_to_update = ",".join(agent_list[offset:limit])
        #print(f"AGENTS: {agents_to_update}", offset, limit)
        
        update_request = requests.put(WAZUH_API + f"/agents/upgrade?agents_list={agents_to_update}&pretty=true", headers=HEADERS, verify=VERIFY)
        
        if update_request.status_code == 200:
            print(f"Update successful on agents: {agents_to_update}")

            # Iterate if there are more agents to be updated
            if len(agent_list) > limit:
                agents_to_update = ""
                offset = limit
                limit = limit + batch
                if limit > len(agent_list):
                    limit = len(agent_list)
            else:
                # Finished updating
                print("Update finished")
                finish = True

        else:
            if update_request.status_code == 401:
                # Renew token
                get_token()
            else:
                raise Exception(f"Error obtaining response: {update_request.json()}")

def main():
    # Get first token
    get_token()

    # Gather outdated agents
    outdated_agents = get_outdated()

    # Update agents if there is any
    if outdated_agents:
        update_agents(outdated_agents)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--env_id', type=str, required=True, help='Wazuh Cloud environment id.')
    parser.add_argument('-u', '--user', type=str, required=True, help='Wazuh API user.')
    parser.add_argument('-p', '--password', type=str, required=True, help='Wazuh API password.')
    args = parser.parse_args()

    WAZUH_ID = args.env_id
    WAZUH_USER = args.user
    WAZUH_PASS = args.password

    WAZUH_API=f"https://{WAZUH_ID}.cloud.wazuh.com/api/wazuh"

    main()