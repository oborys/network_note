#! /usr/bin/env python3

import json
import requests
import urllib3
from requests.auth import HTTPBasicAuth




dnac_devices = ['Hostname','Platform Id','Software Type','Software Version','Up Time' ]


# Silence the insecure warning due to SSL Certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
              'content-type': "application/json",
              'x-auth-token': ""
          }

dnac = {
        "host": "sandboxdnac.cisco.com",
        "port": 443,
        "username": "devnetuser",
        "password": "Cisco123!"
    }

def dnac_login(host, username, password):
    url = "https://{}/api/system/v1/auth/token".format(host)
    response = requests.request("POST", url, auth=HTTPBasicAuth(username, password),
                                headers=headers, verify=False)
    return response.json()["Token"]


def network_device_list(dnac, token):
    url = "https://{}/api/v1/network-device".format(dnac['host'])
    headers["x-auth-token"] = token
    response = requests.get(url, headers=headers, verify=False)
    data = response.json()
    for item in data['response']:
        print(item["hostname"],"  ", item["managementIpAddress"])



login = dnac_login("sandboxdnac.cisco.com", "devnetuser", "Cisco123!")
network_device_list(dnac, login)

print(dnac_devices)
