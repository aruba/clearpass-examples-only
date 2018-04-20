#!/usr/bin/env python3
#------------------------------------------------------------------------------
#
# Author: @timcappalli, Aruba Security Group
# Organization: Aruba, a Hewlett Packard Enterprise company
#
# Version: 2018.01
#
#
# Copyright (c) Hewlett Packard Enterprise Development LP
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
#------------------------------------------------------------------------------

__version__ = "2018.01"

_USAGE = '''
disconnect_compromised.py <mac-address>
'''

import requests
import json
import sys
import os
import re
from configparser import ConfigParser

# grab  MAC from argument
if len(sys.argv) == 2:
    raw_mac = sys.argv[1]
else:
    print('ERROR: No MAC address passed. \nPass MAC address as argument. ex: disconnect_compromised.py 00:01:aa:bb:cc:dd')
    exit(1)


# configuration file parameters
params = os.path.join(os.path.dirname(__file__), "config/params.cfg")
config = ConfigParser()
config.read(params)

clearpass_fqdn = config.get('ClearPass', 'clearpass_fqdn')
oauth_grant_type = config.get('OAuth 2.0', 'grant_type')
oauth_client_id = config.get('OAuth 2.0', 'client_id')
oauth_client_secret = config.get('OAuth 2.0', 'client_secret')
oauth_username = config.get('OAuth 2.0', 'username')
oauth_password = config.get('OAuth 2.0', 'password')


# validate config
def check_config(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password):
    """Validate the OAuth 2.0 configuration from the params.cfg file."""

    if not clearpass_fqdn:
        print('Error: ClearPass FQDN must be defined in config file (config/params.cfg)')
        exit(1)
    if not oauth_grant_type:
        print('Error: grant_type must be defined in config file (config/params.cfg)')
        exit(1)
    if not oauth_client_id:
        print('Error: client_id must be defined in config file (config/params.cfg)')
        exit(1)
    if oauth_grant_type == "password" and (not oauth_username or not oauth_password):
        print('Error: username and password must be defined in config file for password grant type (config/params.cfg)')
        exit(1)


def get_access_token(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password):
    """Get OAuth 2.0 access token with config from params.cfg"""

    url = "https://" + clearpass_fqdn + "/api/oauth"

    headers = {'Content-Type': 'application/json'}

    # grant_type: password
    if oauth_grant_type == "password":
        payload = {'grant_type': oauth_grant_type, 'username': oauth_username, 'password': oauth_password, 'client_id': oauth_client_id, 'client_secret': oauth_client_secret}

        try:
            r = requests.post(url, headers=headers, json=payload)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response['access_token']

    # grant_type: password   public client
    if oauth_grant_type == "password" and not oauth_client_secret:
        payload = {'grant_type': oauth_grant_type, 'username': oauth_username, 'password': oauth_password, 'client_id': oauth_client_id}

        try:
            r = requests.post(url, headers=headers, json=payload)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response['access_token']

    # grant_type: client_credentials
    if oauth_grant_type == "client_credentials":
        payload = {'grant_type': oauth_grant_type, 'client_id': oauth_client_id, 'client_secret': oauth_client_secret}

        try:
            r = requests.post(url, headers=headers, json=payload)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response['access_token']


def normalize_mac(raw_mac: str) -> str:
    mac = re.sub('[.:-]', '', raw_mac).lower()
    return mac


def mark_compromised(clearpass_fqdn, mac_addr, access_token):

    url = "https://" + clearpass_fqdn + "/api/endpoint/mac-address/" + mac_addr

    payload = "{\n  \"attributes\": {\n    \"Compromised\": \"true\"\n  }\n}"
    headers = {
        'authorization': "Bearer {}".format(access_token),
        'content-type': "application/json"
    }

    try:
        r = requests.patch(url, data=payload, headers=headers)
        r.raise_for_status()
    except Exception as e:
        if r.status_code == 404:
            print("ERROR: Endpoint not found.")
            exit(1)
        else:
            print(e)
            exit(1)

    if r.status_code == 200:
        print("SUCCESS! Endpoint marked as compromised.\n")
        return True
    else:
        print("ERROR: Could not mark endpoint.")
        print("\t{}".format(r.text))
        exit(1)


def get_sessions(clearpass_fqdn, mac_addr, access_token):

    url = "https://" + clearpass_fqdn + "/api/session"

    querystring = {'filter': json.dumps({"acctstoptime": {"$exists": False}, "mac_address": mac_addr}),
                   'calculate_count': 'true'}

    headers = {
        'authorization': "Bearer {}".format(access_token),
        'content-type': "application/json"
    }

    r = requests.get(url, headers=headers, params=querystring)

    response = r.json()

    if response['count'] > 0:
        sessionid = [(i['id']) for i in response['_embedded']['items'] if not i['acctstoptime']]
        return sessionid[0]
    elif response['count'] == 0:
        print("No active sessions found. Disconnect not requested.")
        exit(0)
    else:
        print("Active sessions could not be retrieved")
        exit(1)


def active_session_disconnect(clearpass_fqdn, sessionid, access_token):

    url = "https://" + clearpass_fqdn + "/api/session/" + sessionid + "/disconnect"

    headers = {
        'authorization': "Bearer {}".format(access_token),
        'content-type': "application/json"
    }

    payload = {"confirm_disconnect": "1"}

    r = requests.post(url, data=json.dumps(payload), headers=headers)

    response = r.json()
    message = response['message']

    return message


if __name__ == '__main__':

    check_config(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password)

    access_token = get_access_token(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password)

    mac_addr = normalize_mac(raw_mac)

    mark_compromised(clearpass_fqdn, mac_addr, access_token)

    sessionid = get_sessions(clearpass_fqdn, mac_addr, access_token)

    disconnect = active_session_disconnect(clearpass_fqdn, sessionid, access_token)

    print(disconnect)

