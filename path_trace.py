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


import requests
import json
import urllib3
import time
import ipaddress

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

from config import DNAC_URL, DNAC_PASS, DNAC_USER

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data: data to pretty print
    :return None
    """
    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))


def get_dnac_jwt_token(dnac_auth):
    """
    Create the authorization token required to access Cisco DNA Center
    Call to Cisco DNA Center- /api/system/v1/auth/login
    :param dnac_auth - Cisco DNA Center Basic Auth string
    :return Cisco DNA Center Auth Token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    response_json = response.json()
    dnac_jwt_token = response_json['Token']
    return dnac_jwt_token


def create_path_trace(src_ip, src_port, dest_ip, dest_port, protocol, dnac_jwt_token):
    """
    This function will create a new Path Trace between the source IP address {src_ip} and the
    destination IP address {dest_ip}.
    The
    :param src_ip: Source IP address
    :param src_port: Source port, range (1-65535) or 'None'
    :param dest_ip: Destination IP address
    :param dest_port: Destination port, range (1-65535) or 'None'
    :param protocol: IP Protocol, range (1-254) or 'None'
    :param dnac_jwt_token: Cisco DNA Center token
    :return: Cisco DNA Center path visualisation id
    """

    param = {
        'destIP': dest_ip,
        'sourceIP': src_ip,
        'periodicRefresh': False,
        'inclusions': [
            'INTERFACE-STATS',
            'DEVICE-STATS',
            'ACL-TRACE',
            'QOS-STATS'
        ]
    }
    if src_port is not '':
        param.update({'sourcePort': src_port})
    if dest_port is not '':
        param.update({'destPort': dest_port})
    if protocol is not '':
        param.update({'protocol': protocol})

    # print the path trace details
    print('\nInitiated Path Trace with these parameters:')
    pprint(param)
    url = DNAC_URL + '/dna/intent/api/v1/flow-analysis'
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    path_response = requests.post(url, data=json.dumps(param), headers=header, verify=False)
    path_json = path_response.json()
    path_id = path_json['response']['flowAnalysisId']
    return path_id


def get_path_trace_info(path_id, dnac_jwt_token):
    """
    This function will return the path trace details for the path visualisation {id}
    :param path_id: Cisco DNA Center path visualisation id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: Path visualisation status, and the details in a list [device,interface_out,interface_in,device...]
    """
    # check every 10 seconds to see if path trace completed
    path_status = 'INPROGRESS'
    while path_status == 'INPROGRESS':

        # wait 2 seconds for the path trace to be completed
        time.sleep(2)

        url = DNAC_URL + '/dna/intent/api/v1/flow-analysis/' + path_id
        header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        path_response = requests.get(url, headers=header, verify=False)
        path_json = path_response.json()
        path_info = path_json['response']
        path_status = path_info['request']['status']

    path_list = []
    if path_status == 'COMPLETED':
        # print the complete Path Trace output
        print('\n\nThe complete path trace info is: \n')
        pprint(path_info)
        network_info = path_info['networkElementsInfo']
        path_list.append(path_info['request']['sourceIP'])
        for elem in network_info:
            try:
                path_list.append(elem['ingressInterface']['physicalInterface']['name'])
            except:
                pass
            try:
                path_list.append(elem['name'])
            except:
                pass
            try:
                path_list.append(elem['egressInterface']['physicalInterface']['name'])
            except:
                pass
        path_list.append(path_info['request']['destIP'])
        return path_status, path_list
    else:
        if path_status == 'FAILED':
            path_error = [path_info['request']['failureReason']]
            return path_status, path_error
        else:
            return 'Something went wrong', ''


def validate_ipv4_address(ipv4_address):
    """
    This function will validate if the provided string is a valid IPv4 address
    :param ipv4_address: string with the IPv4 address
    :return: true/false
    """
    try:
        ipaddress.ip_address(ipv4_address)
        return True
    except:
        return False


def main():
    """
    This sample script will:
    - ask the user to enter the source and destination node IPv4 address and optional the source and destination port,
    optional protocol
    - validate if the entered IPv4 addresses, ports and protocol numbers are valid
    - start the Cisco DNA Center Path Trace for the above endpoints
    - retrieve the Path Trace result
    """

    # obtain the Cisco DNA Center Auth Token
    dnac_token = get_dnac_jwt_token(DNAC_AUTH)

    # ask user for the input of the IPv4 addresses and ports, protocol
    # validate if the entered IPv4 addresses are valid

    # enter and validate source ip address
    while True:
        source_ip = input('Input the source IPv4 Address:   ')
        if validate_ipv4_address(source_ip) is True:
            break
        else:
            print('IPv4 address is not valid')

    # enter and validate the source port
    while True:
        value = input('Input the source port number (or Enter for none):   ')
        if value is '':
            source_port = value
            break
        else:
            try:
                source_port = int(value)
                if 1 <= source_port <= 65535:
                    break
                else:
                    print('Invalid port number entered')
            except:
                print('Invalid port number entered')

    # enter and validate the destination ip address
    while True:
        destination_ip = input('Input the destination IPv4 Address:   ')
        if validate_ipv4_address(destination_ip) is True:
            break
        else:
            print('IPv4 address is not valid')

    # enter and validate the destination port
    while True:
        value = input('Input the destination port number (or Enter for none):   ')
        if value is '':
            destination_port = value
            break
        else:
            try:
                destination_port = int(value)
                if 1 <= destination_port <= 65535:
                    break
                else:
                    print('Invalid port number entered')
            except:
                print('Invalid protocol number entered')

    # enter and validate the protocol number
    while True:
        value = input('Input the protocol number (or Enter for none):   ')
        if value is '':
            protocol = value
            break
        else:
            try:
                protocol = int(value)
                if 1 <= protocol <= 254:
                    break
                else:
                    print('Invalid protocol number entered')
            except:
                print('Invalid protocol number entered')

    # create path trace
    path_trace_id = create_path_trace(source_ip, source_port, destination_ip, destination_port, protocol, dnac_token)

    # print the path trace id
    print('\nInitiated Path Trace with the id: \n' + path_trace_id)

    path_trace_result = get_path_trace_info(path_trace_id, dnac_token)
    print('\nPath Trace status: ', path_trace_result[0])
    print('\nPath Trace result:')
    pprint(path_trace_result[1])

    print('\n\nEnd of Application "path_trace.py" Run')


if __name__ == "__main__":
    main()

