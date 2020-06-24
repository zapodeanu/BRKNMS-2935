#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TME, Enterprise Networking, Cisco Systems


# import Python packages


import urllib3
import time
import datetime
import logging
import sys
import requests
import json
import select
import re
import urllib3

# import functions modules

import utils
import webex_teams_apis
import dnac_apis
import asav_apis
import config
import netconf_restconf
import service_now_apis
import ucsd_apis

from PIL import Image, ImageDraw, ImageFont  # for image processing
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth


from config import WEBEX_TEAMS_AUTH, WEBEX_TEAMS_URL
from config import GOOGLE_API_KEY
from config import DNAC_URL, DNAC_USER, DNAC_PASS
from config import ASAv_URL, ASAv_USER, ASAv_PASSW
from config import UCSD_URL, UCSD_KEY
from config import SNOW_URL, SNOW_ADMIN, SNOW_PASS
from config import APPROVER_EMAIL

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)
ASAv_AUTH = HTTPBasicAuth(ASAv_USER, ASAv_PASSW)

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

# The following declarations need to be updated based on your lab environment

# Webex Teams related
ROOM_NAME = 'ERNA Automation'


# UCSD related
UCSD_CONNECT_FLOW = 'Gabi_VM_Connect_VLAN_10'
UCSD_DISCONNECT_FLOW = 'Gabi_VM_Disconnect_VLAN_10'

# VDI IPv4 address
VDI_IP = '172.16.203.50'

# ASAv
OUTSIDE_INT = 'outside'


def main():
    """
    Vendor will join Webex Teams Room with the name {ROOM_NAME}
    It will ask for access to an IP-enabled device - named {IPD}
    The code will map this IP-enabled device to the IP address {10.93.140.35}
    Access will be provisioned to allow connectivity from DMZ VDI to IPD
    """

    # save the initial stdout
    initial_sys = sys.stdout

    # the user will be asked if interested to run in demo mode or in
    # production (logging to files - erna_log.log, erna_err.log))

    user_input = utils.get_input_timeout('If running in Demo Mode please enter y ', 10)

    user_input = 'y'  # remove this line if you want to run in production
    if user_input != 'y':

        # open a log file 'erna.log'
        file_log = open('erna_log.log', 'w')

        # open an error log file 'erna_err.log'
        err_log = open('erna_err.log', 'w')

        # redirect the stdout to file_log and err_log
        sys.stdout = file_log
        sys.stderr = err_log

        # configure basic logging to send to stdout, level DEBUG, include timestamps
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format='%(asctime)s - %(levelname)s - %(message)s')

    # logging, debug level, to file {erna_run.log}
    logging.basicConfig(
        filename='erna_run.log',
        level=logging.DEBUG,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    # the local date and time when the code will start execution

    date_time = str(datetime.datetime.now().replace(microsecond=0))
    print('\nThe Application "ERNA.py" started running at this time ' + date_time)

    user_input = utils.get_input_timeout('Enter y to skip next section : ', 10)

    user_input = 'y' # remove this line if you want to follow the approval process

    if user_input != 'y':
        # verify if Webex Teams Space exists, if not create Webex Teams Space, and add membership (optional)

        webex_teams_room_id = webex_teams_apis.get_space_id(ROOM_NAME)
        if webex_teams_room_id is None:
            webex_teams_room_id = webex_teams_apis.create_space(ROOM_NAME)
            print('- ', ROOM_NAME, ' -  Webex Teams room created')

            # invite membership to the room
            webex_teams_apis.add_space_membership(ROOM_NAME, APPROVER_EMAIL)

            webex_teams_apis.post_space_message(ROOM_NAME, 'To require access enter :  IPD')
            webex_teams_apis.post_space_message(ROOM_NAME, 'Ready for input!')
            print('Instructions posted in the room')
        else:
            print('- ', ROOM_NAME, ' -  Existing Webex Teams room found')

            webex_teams_apis.post_space_message(ROOM_NAME, 'To require access enter :  IPD')
            webex_teams_apis.post_space_message(ROOM_NAME, 'Ready for input!')
        print('- ', ROOM_NAME, ' -  Webex Teams room id: ', webex_teams_room_id)

        # check for messages to identify the last message posted and the user's email who posted the message
        # check for the length of time required for access

        last_message = (webex_teams_apis.last_user_message(ROOM_NAME))[0]

        while last_message == 'Ready for input!':
            time.sleep(5)
            last_message = (webex_teams_apis.last_user_message(ROOM_NAME))[0]
            if last_message == 'IPD':
                last_person_email = (webex_teams_apis.last_user_message(ROOM_NAME))[1]
                webex_teams_apis.post_space_message(ROOM_NAME, 'How long time do you need access for? (in minutes)  : ')
                time.sleep(10)
                if (webex_teams_apis.last_user_message(ROOM_NAME))[0] == 'How long time do you need access for? (in minutes)  : ':
                    timer = 30 * 60
                else:
                    timer = int(webex_teams_apis.last_user_message(ROOM_NAME)[0]) * 60
            elif last_message != 'Ready for input!':
                webex_teams_apis.post_space_message(ROOM_NAME, 'I do not understand you')
                webex_teams_apis.post_space_message(ROOM_NAME, 'To require access enter :  IPD')
                webex_teams_apis.post_space_message(ROOM_NAME, 'Ready for input!')
                last_message = 'Ready for input!'

        print('\nThe user with this email: ', last_person_email, ' asked access to IPD for ', (timer/60), ' minutes')

    # get the WJT Auth token to access DNA
    dnac_token = dnac_apis.get_dnac_jwt_token(DNAC_AUTH)
    print('\nThe DNA Center auth token is: ', dnac_token)

    # IPD IP address - DNS lookup if available

    IPD_IP = '10.93.140.35'
    last_person_email = 'gzapodea@cisco.com'
    approver_email = 'gabi@cisco.com'
    timer = 3600

    # locate IPD in the environment using DNA C
    ipd_location_info = dnac_apis.locate_client_ip(IPD_IP, dnac_token)

    remote_device_hostname = ipd_location_info[0]  # the network device the IPD is connected to
    vlan_number = ipd_location_info[2]  # the access VLAN number
    interface_name = ipd_location_info[1]  # the interface number is connected to

    device_location = dnac_apis.get_device_location(remote_device_hostname, dnac_token)  # network device location
    location_list_info = device_location.split('/')
    remote_device_location = location_list_info[-1]  # select the building name

    log_ipd_info = '\n\nThe IPD is connected to this device: ' + remote_device_hostname
    log_ipd_info += '\n\nThis interface: ' + interface_name + ', access VLAN: ' + vlan_number
    log_ipd_info += '\n\nLocated       : ' + remote_device_location
    print(log_ipd_info)

    # request approval

    if user_input != 'y':
        webex_teams_apis.post_space_message(ROOM_NAME, ('The user with this email ' + last_person_email +
                                                        ' asked access to IPD for ' + str(timer / 60) + ' minutes'))
        webex_teams_apis.post_space_message(ROOM_NAME, 'The IPD is connected to the switch ' + remote_device_hostname +
                                            ' at our location ' + remote_device_location)
        webex_teams_apis.post_space_message(ROOM_NAME, 'To approve enter: Y/N')

        # check for messages to identify the last message posted and the user's email who posted the message.
        # looking for user - Director email address, and message = 'Y'

        last_message = (webex_teams_apis.last_user_message(ROOM_NAME))[0]

        while last_message == 'To approve enter: Y/N':
            time.sleep(5)
            last_message = (webex_teams_apis.last_user_message(ROOM_NAME))[0]
            approver_email = (webex_teams_apis.last_user_message(ROOM_NAME))[1]
            if last_message == 'y' or 'Y':
                if approver_email == APPROVER_EMAIL:
                    print('Access Approved')
                else:
                    last_message = 'To approve enter: Y/N'

        print('\nApproval process completed')

    # get UCSD API key
    # ucsd_key = ucsd_apis.get_ucsd_api_key()

    # execute UCSD workflow to connect VDI to VLAN, power on VDI
    # ucsd_apis.execute_ucsd_workflow(ucsd_key, UCSD_CONNECT_FLOW)

    log_ucsd_info = '\n\nUCSD connect flow executed'
    print(log_ucsd_info)

    # deployment of cli configuration files to the dc router

    dc_device_hostname = 'PDX-RO'
    template_project = 'ERNA'
    print('\nThe DC device name is: ', dc_device_hostname)

    dc_config_file = 'DC_Config.txt'
    dc_config_templ = dc_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(dc_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    # validation of dc router cli template
    dc_valid = dnac_apis.check_ipv4_duplicate(dc_config_file)
    log_dc_info = ''
    if dc_valid is False:
        print('\n\nDC Router CLI Template validated')
        log_dc_info = '\n\nDC Router CLI Templates validated'

    dnac_apis.upload_template(dc_config_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_dc = dnac_apis.deploy_template(dc_config_templ, template_project, dc_device_hostname, dnac_token)  # deploy dc template

    log_dc_info += '\n\nDeployment of the configurations to the DC router, ' + dc_device_hostname
    log_dc_info += ' started, deployment id: ' + depl_id_dc
    log_dc_config = '\nDC Router Config \n\n' + cli_config
    print(log_dc_info)

    time.sleep(1)

    # deployment of cli configuration files to the remote router

    remote_config_file = 'Remote_Config.txt'
    remote_config_templ = remote_config_file.split('.')[0]  # select the template name from the template file

    cli_file = open(remote_config_file, 'r')  # open file with the template
    cli_config = cli_file.read()  # read the file

    # update the template with the localized info for the IPD
    # replace the $VlanId with the localized VLAN access
    # replace the $IPD with the IPD ip address

    cli_config = cli_config.replace('$IPD', IPD_IP)
    cli_config = cli_config.replace('$VlanId', vlan_number)

    remote_updated_config_file = 'Remote_Config_Updated.txt'
    updated_cli_file = open(remote_updated_config_file, 'w')
    updated_cli_file.write(cli_config)
    updated_cli_file.close()

    # validation of remote router cli template
    remote_valid = dnac_apis.check_ipv4_duplicate(remote_updated_config_file)
    log_remote_info = ''
    if remote_valid is False:
        log_remote_info = '\n\nRemote Device CLI Template validated'
        print(log_remote_info)

    dnac_apis.upload_template(remote_config_templ, template_project, cli_config, dnac_token)  # upload the template to DNA C
    depl_id_remote = dnac_apis.deploy_template(remote_config_templ, template_project, remote_device_hostname, dnac_token)   # deploy remote template
    time.sleep(1)

    log_remote_info += '\n\nDeployment of the configurations to the Remote device, ' + remote_device_hostname
    log_remote_info += ' started, deployment id: ' + depl_id_remote
    log_remote_config = '\nRemote Device Config \n\n' + cli_config
    print(log_remote_info)

    time.sleep(1)

    # check the deployment status after waiting for all jobs to complete - 10 seconds
    print('\nWait for DNA Center to complete template deployments')
    time.sleep(10)

    dc_status = dnac_apis.check_template_deployment_status(depl_id_dc, dnac_token)
    remote_status = dnac_apis.check_template_deployment_status(depl_id_remote, dnac_token)

    log_templ_depl_info = '\n\nTemplates deployment status DC: ' + dc_status + ', Remote: ' + remote_status
    print(log_templ_depl_info)

    if dc_status == 'SUCCESS' and remote_status == 'SUCCESS':
        print('\nAll templates deployment have been successful\n')
        templ_deploy_status = True

    # synchronization of devices configured - DC and Remote Router
    dc_sync_status = dnac_apis.sync_device(dc_device_hostname, dnac_token)[0]
    remote_sync_status = dnac_apis.sync_device(remote_device_hostname, dnac_token)[0]

    if dc_sync_status == 202:
        print('\nDNA Center started the DC Router resync')
    if remote_sync_status == 202:
        print('\nDNA Center started the Remote Router resync')

    dc_router_tunnel = netconf_restconf.get_restconf_int_oper_status('Tunnel201')
    remote_router_tunnel = netconf_restconf.get_netconf_int_oper_status('Tunnel201')

    log_tunnel_info = '\n\nThe Tunnel 201 interfaces operational state: '
    log_tunnel_info += '\n\nFrom ' + remote_device_hostname + ' using NETCONF - ' + dc_router_tunnel
    log_tunnel_info += '\n\nFrom ' + dc_device_hostname + ' using RESTCONF - ' + remote_router_tunnel

    print(log_tunnel_info)

    print('\nWait for DNA Center to complete the resync of the two devices')

    time.sleep(180)

    print('\nSync completed, Path Trace started')
    # start a path trace to check the path segmentation
    path_trace_id = dnac_apis.create_path_trace('172.16.202.1', IPD_IP, dnac_token)

    print('\nWait for Path Trace to complete')
    time.sleep(30)

    path_trace_info = dnac_apis.get_path_trace_info(path_trace_id, dnac_token)

    log_path_trace = '\n\nPath Trace status: ' + path_trace_info[0]
    log_path_trace += '\n\nPath Trace details: ' + str(path_trace_info[1])
    print(log_path_trace)

    # create ASAv outside interface ACL to allow traffic

    outside_acl_id = asav_apis.get_asav_access_list(OUTSIDE_INT)
    asav_status = asav_apis.create_asav_access_list(outside_acl_id, OUTSIDE_INT, VDI_IP, IPD_IP)
    if asav_status == 201:
        log_asav_info = '\n\nASAv access list updated to allow traffic from ' + VDI_IP + ' to ' + IPD_IP + ' on the interface ' + OUTSIDE_INT
    else:
        log_asav_info = '\n\nError updating the ASAv access list on the interface ' + OUTSIDE_INT
    print(log_asav_info)

    # Webex Teams notification

    webex_teams_apis.post_space_message(ROOM_NAME, 'Requested access to this device: IPD, located in our office: ' +
                                        remote_device_location + ' by user ' + last_person_email + ' has been granted for '
                                        + str(int(timer / 60)) + ' minutes')
    log_access_info = '\n\nRequested access to this device: IPD, located in our office: '
    log_access_info += remote_device_location + ' by user: ' + last_person_email + ' has been granted for ' + str(int(timer / 60)) + ' minutes'

    # create and update ServiceNow incident

    snow_user = 'ERNA'
    snow_description = 'ERNA Automation - Vendor Remote Access to IPD: ' + IPD_IP

    snow_incident = service_now_apis.create_incident(snow_description, log_ipd_info, snow_user, '2')
    comments = log_ucsd_info + log_dc_info + log_dc_config + log_remote_info + log_remote_config + log_templ_depl_info
    comments += log_tunnel_info + log_path_trace + log_asav_info + log_access_info
    service_now_apis.update_incident(snow_incident, comments, snow_user)

    date_time = str(datetime.datetime.now().replace(microsecond=0))
    print('\n\nEnd of application "ERNA.py" provisioning run at this time ', date_time)

    # time.sleep(timer)  # un-comment this line if time limit is required
    input('Press any key to continue de-provisioning  ')

    #
    #  restore configurations to initial state
    #

    #  restore DC router config

    dc_rem_file = 'DC_Remove.txt'
    dc_rem_templ = dc_rem_file.split('.')[0]

    cli_file = open(dc_rem_file, 'r')
    cli_config = cli_file.read()

    dnac_apis.upload_template(dc_rem_templ, template_project, cli_config, dnac_token)
    depl_id_dc_rem = dnac_apis.deploy_template(dc_rem_templ, template_project, dc_device_hostname, dnac_token)

    print('\nDC Router restored to the baseline configuration')
    log_remove_info = '\n\nDC Router restored to the baseline configuration'

    time.sleep(1)

    #  restore Remote router config

    remote_rem_file = 'Remote_Remove.txt'
    remote_rem_templ = remote_rem_file.split('.')[0]

    cli_file = open(remote_rem_file, 'r')
    cli_config = cli_file.read()

    # update the template with the local info for the IPD
    # replace the $VlanId with the local VLAN access
    # replace the $IPD with the IPD ip address

    cli_config = cli_config.replace('$IPD', IPD_IP)
    cli_config = cli_config.replace('$VlanId', vlan_number)

    remote_updated_remove_file = 'Remote_Remove_Updated.txt'
    updated_cli_file = open(remote_updated_remove_file, 'w')
    updated_cli_file.write(cli_config)
    updated_cli_file.close()

    dnac_apis.upload_template(remote_rem_templ, template_project, cli_config, dnac_token)
    depl_id_remote_rem = dnac_apis.deploy_template(remote_rem_templ, template_project, remote_device_hostname, dnac_token)

    print('\nRemote Router restored to the baseline configuration')
    log_remove_info += '\n\nRemote Device restored to the baseline configuration'

    time.sleep(1)

    # remove the ASAv outside interface ACLE that allowed traffic between VDI and IPD

    outside_acl_id = asav_apis.get_asav_access_list(OUTSIDE_INT)
    asav_status = asav_apis.delete_asav_access_list(outside_acl_id, OUTSIDE_INT)
    if asav_status == 204:
        log_asav_remove_info = '\n\nASAv access list on the interface ' + OUTSIDE_INT + ' restored to the baseline configuration'
    else:
        log_asav_remove_info = 'Error while restoring the ASAv access list on the interface ' + OUTSIDE_INT
    print(log_asav_remove_info)

    # execute UCSD workflow to disconnect VDI to VLAN, power on VDI
    # ucsd_apis.execute_ucsd_workflow(ucsd_key, UCSD_DISCONNECT_FLOW)

    log_ucsd_remove_info = '\n\nUCSD disconnect flow executed'
    print(log_ucsd_remove_info)

    # sync the remote and DC device
    dc_sync_status = dnac_apis.sync_device(dc_device_hostname, dnac_token)[0]
    remote_sync_status = dnac_apis.sync_device(remote_device_hostname, dnac_token)[0]

    log_sync_info = ''
    if dc_sync_status == 202:
        log_sync_info = '\n\nDNA Center started the DC Router resync'
    if remote_sync_status == 202:
        log_sync_info += '\n\nDNA Center started the Remote Router resync'

    print(log_sync_info)

    # Webex Teams notification

    webex_teams_apis.post_space_message(ROOM_NAME, 'Access to this device: IPD has been terminated')
    webex_teams_apis.post_space_message(ROOM_NAME, '----------------------------------------------')

    # update the database with script execution

    access_log_file = open('access_logs.csv', 'a')
    data_to_append = str('\n\n' + date_time) + ','
    access_log_file.write(data_to_append)
    data_to_append = last_person_email + ',' + log_ipd_info + ',' + approver_email
    data_to_append += ',' + log_dc_info + ',' + log_remote_info + ',' + log_templ_depl_info + ','
    data_to_append += log_path_trace + ',' + log_asav_info + ',\n' + snow_incident
    data_to_append_nolines = data_to_append.replace('\n\n', '\n')
    access_log_file.write(data_to_append_nolines)
    access_log_file.close()

    print('\nRecords database updated, file saved')

    comments = log_remove_info + log_asav_remove_info + log_ucsd_remove_info + log_sync_info
    service_now_apis.update_incident(snow_incident, comments, snow_user)

    # restore the stdout to initial value
    sys.stdout = initial_sys

    # the local date and time when the code will end execution

    date_time = str(datetime.datetime.now().replace(microsecond=0))
    print('\n\nEnd of application "ERNA.py" run at this time ', date_time)


if __name__ == '__main__':
    main()
