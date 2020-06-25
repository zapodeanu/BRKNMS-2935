#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

Cisco DNA Center Path Trace

Copyright (c) 2019 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import json

import requests
import urllib3
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from config import RO_HOST, PASS, USER

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


ROUTER_AUTH = HTTPBasicAuth(USER, PASS)


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data:
    :return:
    """

    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))


def get_restconf_int_oper_status(interface):

    url = 'https://' + RO_HOST + '/restconf/data/interfaces-state/interface=' + interface
    header = {'Content-type': 'application/yang-data+json', 'accept': 'application/yang-data+json'}
    response = requests.get(url, headers=header, verify=False, auth=ROUTER_AUTH)
    interface_info = response.json()
    oper_data = interface_info['ietf-interfaces:interface']
    return oper_data


# get interface operation data using RESTCONF


json_info = get_restconf_int_oper_status('GigabitEthernet1')
pprint(json_info)
