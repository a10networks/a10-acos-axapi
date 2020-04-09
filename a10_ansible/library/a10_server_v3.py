#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: a10_server
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb server objects on A10 Networks devices via aXAPI
author: Fadi Hafez
notes:
    - Requires A10 Networks aXAPI 3.0
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    aliases: ['user', 'admin']
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    aliases: ['pass', 'pwd']
  partition:
    description:
      - L3V partition to add these servers to
    required: false
    default: null
    choices: []
  server_name:
    description:
      - slb server name
    required: true
    aliases: ['server']
  server_ip:
    description:
      - slb server IP address
    required: false
    default: null
    aliases: ['ip', 'address']
  server_status:
    description:
      - slb virtual server status
    required: false
    default: enabled
    aliases: ['status']
    choices: ['enabled', 'disabled']
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a
        dictionary which specifies the C(port:) and C(protocol:) and C(health_monitor:), but can also optionally
        specify the C(status:). See the examples below for details. This parameter is
        required when C(state) is C(present).  Health Monitor must already exist.
    required: false
    default: null
  server_hm:
    description:
      - A health monitor name to bind to this server.  The health monitor must already exist.
    required: false
    default: null
  port_num:
    description:
      - The port number on the server listening for the service.
    required: false
    default: null
  protocol:
    description:
      - The protocol (tcp/udp) that the server is listening to.
    required: false
    choices: ['udp','tcp']
    default: tcp
  health_monitor:
    description:
      - A health monitor name to bind to this server.  The health monitor must already exist.
    required: false
    default: null
  overwrite:
    description:
      - If the server is found, should you overwrite or just ignore it
        only applicable when state == present
    required: false
    default: 'no'
    choices: ['yes', 'no']
  state:
    description:
      - create, update or remove slb server
    required: false
    default: present
    choices: ['present', 'absent']
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: 'no'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new server
- a10_server_v3: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    server: test
    server_ip: 1.1.1.100
    server_hm: hm_icmp
    server_ports:
      - port-number: 8080
        protocol: tcp
        health-check: ws_hm_http
      - port-number: 8443
        protocol: TCP
        health-check: ws_hm_https

'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            server_name=dict(type='str', aliases=['server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address']),
            server_action=dict(type='str', default='enable', aliases=['status'], choices=['enable', 'disable']),
            server_ports=dict(type='list', aliases=['port'], default=[]),
            server_hm=dict(type='str', aliases=['health_monitor']),
            overwrite=dict(type='bool', default=False, required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    state = module.params['state']
    write_config = module.params['write_config']
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_action = module.params['server_action']
    slb_server_ports = module.params['server_ports']
    slb_server_hm = module.params['server_hm']
    overwrite = module.params['overwrite']

    if slb_server is None:
        module.fail_json(msg='server_name is required')

    axapi_base_url = 'http://%s/axapi/v3/' % host
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)
    
    # change partitions if we need to
    if part:
        part_change_result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (part_change_result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=part_change_result['response']['err']['msg'])

    # create the JSON object containing the parameters
    json_post = {
        'server': {
            'name': slb_server,
        }
    }

    # add optional module parameters
    if slb_server_ip:
        json_post['server']['host'] = slb_server_ip

    if slb_server_ports:
        json_post['server']['port-list'] = slb_server_ports

    if slb_server_hm:
        json_post['server']['health-check'] = slb_server_hm

    if slb_server_action:
        json_post['server']['action'] = slb_server_action
    
#    rsp, info = fetch_url(module, axapi_base_url + 'slb/server/' + slb_server, method='GET', data=json.dumps(None), headers={'content-type': 'application/json', 'Authorization': 'A10 %s' % signature})
    
    slb_server_data = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method="GET", signature=signature)
    
    if ('response' in slb_server_data and slb_server_data['response']['status'] == 'fail'):
        if (slb_server_data['response']['code'] == 404):
            server_exists = False
        else:
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=slb_server_data['response']['err']['msg'])
    else:
        #server_content = slb_server_data['response']['data']
        server_content = slb_server_data
        server_exists = True
    
    changed = False
    msg = ""
    
    # server is being added/modified
    if state == 'present':
        
        if server_exists and not overwrite:
            # just exit gracefully with a message
            msg='server exists but not modified'

        elif server_exists and overwrite:
            # overwrite the properties of the server
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method="PUT", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "server %s updated" % slb_server
            
        elif not server_exists:
            # create a new server
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/', method="POST", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "server %s created" % slb_server
        
    elif state == 'absent':
        if server_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + slb_server, method="DELETE", signature=signature)
            changed = True
        else:
            result = dict(msg="the server was not present")

    # log out of the session nicely and exit
    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
    module.exit_json(changed=changed, content=result, msg=msg)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *

if __name__ == '__main__':
    main()
