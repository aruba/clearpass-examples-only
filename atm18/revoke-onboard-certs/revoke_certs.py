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
revoke_certs.py <username>
'''

import sys
import json
import requests
import os
from configparser import ConfigParser

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
            if r.status_code == 400:
                print("ERROR: Check configuration (client_id, client_secret, OAuth2.0 username/password)")
                print("\tRaw Error Text: {}".format(e))
                exit(1)
            else:
                print(e)
                exit(1)
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
            if r.status_code == 400:
                print("ERROR: Check configuration (client_id, OAuth2.0 username/password)")
                print("\tRaw Error Text: {}".format(e))
                exit(1)
            else:
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
            if r.status_code == 400:
                print("ERROR: Check configuration (client_id, client_secret)")
                print("\tRaw Error Text: {}".format(e))
                exit(1)
            else:
                print(e)
                exit(1)

        json_response = json.loads(r.text)

        return json_response['access_token']


def get_onboard_certificates(clearpass_fqdn, access_token, username):
    """Get all valid certificates (not revoked or expired) for user"""

    url = "https://{}/api/certificate".format(clearpass_fqdn)

    queryfilter = {'mdps_user_name': username, 'is_valid':'true'}
    payload = {'filter':json.dumps(queryfilter),'calculate_count':'true'}

    headers = {'Authorization':'Bearer {}'.format(access_token), "Content-Type": "application/json"}

    try:
        r = requests.get(url, headers=headers, params=payload)
        r.raise_for_status()
        json_response = r.json()
    except Exception as e:
        print(e)
        exit(1)

    certs = [(i['id'], i['ca_id']) for i in json_response['_embedded']['items']]

    return certs


def revoke_certificates(clearpass_fqdn, access_token, cert_id, ca_id):
    """Revoke certificate by ID"""

    url = "https://{}/api/certificate/{}/revoke".format(clearpass_fqdn, cert_id)

    headers = {'Authorization':'Bearer {}'.format(access_token), "Content-Type": "application/json"}

    payload = {'ca_id': ca_id, 'confirm_revoke':'1'}

    try:
        r = requests.post(url, headers=headers, json=payload)
        r.raise_for_status()
        json_response = r.json()
    except Exception as e:
        print(e)
        exit(1)

    return json_response



if __name__ == '__main__':

    # grab username from argument
    try:
        username = str(sys.argv[1])
    except IndexError:
        print('ERROR: No username passed to script. \nPass username as argument. ex: revoke_certs.py abc@xyz.com')
        exit(1)

    check_config(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password)

    access_token = get_access_token(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret,
                                    oauth_username, oauth_password)

    certs = get_onboard_certificates(clearpass_fqdn, access_token, username)

    if not certs:
        print("No valid certificates found for user < {} >.".format(username))
        exit(0)
    else:
        for i in certs:
            cert_id = str(i[0])
            ca_id = i[1]

            revoked_cert = revoke_certificates(clearpass_fqdn, access_token, cert_id, ca_id)
            print("Certificate number < {} > revoked!\n\tMAC Address: {} | Device Type: {}".format(str(cert_id), revoked_cert['mdps_mac_address'][0], revoked_cert['mdps_device_type']))
