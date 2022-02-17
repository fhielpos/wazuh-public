#!/usr/bin/env python3

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

def update_agents(outdated_agents, group_agents):
    # Update agent list

    if not group_agents:
        agent_list = outdated_agents
    else:
        # Build agent_list
        agent_list = []
        
        for agent in group_agents:
            if agent in outdated_agents:
                agent_list.append(agent)
    
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

def get_agents_group(group):

    # Get agents in group that are active
    agents_ids = []
    limit = 10000
    offset = 0
    finish = False

    while not finish:
        agents_request = requests.get(WAZUH_API + f"/groups/{group}/agents?status=active&limit={limit}&offset={offset}", headers=HEADERS, verify=VERIFY)

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

def main():
    # Get first token
    get_token()

    # Gather outdated agents
    outdated_agents = get_outdated()

    # Gather agents from group
    if WAZUH_GROUP is not None:
        print(f"Fetching agents from {WAZUH_GROUP}")
        group_agents = get_agents_group(WAZUH_GROUP)
    else:
        group_agents = []

    # Update agents if there is any
    if outdated_agents:
        update_agents(outdated_agents, group_agents)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--url', type=str, required=False, help='Wazuh API url. Example: https//IP:55000')
    parser.add_argument('-u', '--user', type=str, required=True, help='Wazuh API user.')
    parser.add_argument('-p', '--password', type=str, required=True, help='Wazuh API password.')
    parser.add_argument('-g', '--group', type=str, required=False, help="Agent groups")

    args = parser.parse_args()

    if not args.group:
        print("No Wazuh group specified, using all")
        WAZUH_GROUP = None
    else:
        WAZUH_GROUP = args.group

    if not args.url:
        print("No Wazuh URL specified, using localhost")
        WAZUH_API = "https://localhost:55000"
    else:
        WAZUH_API = args.url

    WAZUH_USER = args.user
    WAZUH_PASS = args.password

    main()