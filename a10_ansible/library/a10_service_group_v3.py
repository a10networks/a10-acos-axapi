#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb service-group objects
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
module: a10_service_group
version_added: 1.8
short_description: Manage A10 Networks devices' service groups
description:
    - Manage slb service-group objects on A10 Networks devices via aXAPI
author: Fadi Hafez
notes:
    - Requires A10 Networks aXAPI 3.0
    - When a server doesn't exist and is added to the service-group the server will be created
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
    default: null
    aliases: []
    choices: []
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    default: null
    aliases: ['user', 'admin']
    choices: []
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    default: null
    aliases: ['pass', 'pwd']
    choices: []
  partition:
    description:
      - L3V partition to add these servers to
    required: false
    default: null
    choices: []
  service_group:
    description:
      - slb service-group name
    required: true
    default: null
    aliases: ['service', 'pool', 'group']
    choices: []
  health_monitor:
    description:
      - health monitor name to apply to all servers in the service group.  The health monitor must already exist.
    required: false
    default: null
    choices: []
  reset_on_server_selection_fail:
    description:
      - reset-on-server-selection-fail
    required: false
    default: false
    choices: ['true','false']
  service_group_protocol:
    description:
      - slb service-group protocol
    required: false
    default: tcp
    aliases: ['proto', 'protocol']
    choices: ['tcp', 'udp']
  service_group_method:
    description:
      - slb service-group loadbalancing method
    required: false
    default: round-robin
    aliases: ['method']
    choices: ['round-robin', 'weighted-rr', 'least-connection', 'weighted-least-connection', 'service-least-connection', 'service-weighted-least-connection', 'fastest-response', 'least-request', 'round-robin-strict', 'src-ip-only-hash',
 'src-ip-hash']
  servers:
    description:
      - A list of servers to add to the service group. Each list item should be a
        dictionary which specifies the C(server:) and C(port:), but can also optionally
        specify the C(status:). See the examples below for details.
    required: false
    default: null
    aliases: []
    choices: []
  overwrite:
    description:
      - If the SG is found, should you overwrite or just ignore it
        only applicable when state == present
    required: false
    default: 'no'
    choices: ['yes', 'no']
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    default: "no"
    choices: ["yes", "no"]
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new service-group
- a10_service_group_v3: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: PARTNAME
    service_group: sg-80-tcp
    health_monitor: ws_http_hm
    reset_on_server_selection_fail: true
    overwrite: yes
    servers:
      - server: foo1.mydomain.com
        port: 8080
      - server: foo2.mydomain.com
        port: 8080
      - server: foo3.mydomain.com
        port: 8080
      - server: foo4.mydomain.com
        port: 8080
        status: disabled

'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part']),
            service_group=dict(type='str', aliases=['service', 'pool', 'group'], required=True),
            service_group_protocol=dict(type='str', default='tcp', aliases=['proto', 'protocol'], choices=['tcp', 'udp']),
            service_group_method=dict(type='str', default='round-robin',
                                      aliases=['method'],
                                      choices=['round-robin',
                                               'weighted-rr',
                                               'least-connection',
                                               'weighted-least-connection',
                                               'service-least-connection',
                                               'service-weighted-least-connection',
                                               'fastest-response',
                                               'least-request',
                                               'round-robin-strict',
                                               'src-ip-only-hash',
                                               'src-ip-hash']),
            servers=dict(type='list', aliases=['server', 'member'], default=[]),
            health_monitor=dict(type='str', aliases=['hm']),
            reset_on_server_selection_fail=dict(type='bool', default=False),
            overwrite=dict(type='bool', default=False, required=False),            
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    state = module.params['state']
    write_config = module.params['write_config']
    slb_service_group = module.params['service_group']
    slb_service_group_proto = module.params['service_group_protocol']
    slb_service_group_method = module.params['service_group_method']
    slb_servers = module.params['servers']
    slb_health_monitor = module.params['health_monitor']
    slb_reset_on_server_selection_fail = module.params['reset_on_server_selection_fail']
    overwrite = module.params['overwrite']
    
    if slb_service_group is None:
        module.fail_json(msg='service_group is required')

    axapi_base_url = 'http://%s/axapi/v3/' % host
        
    # build the JSON message structure
    json_post = {
        'service-group': {
            'name': slb_service_group,
            'protocol': slb_service_group_proto,
            'lb-method': slb_service_group_method,
            'reset-on-server-selection-fail': slb_reset_on_server_selection_fail,
            'member-list': []
        }
    }

    if slb_health_monitor:
        json_post['service_group']['health_monitor'] = slb_health_monitor

    # first we authenticate to get a session id
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)

    # change partitions if we need to
    if part:
        result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error            
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])

    # validate that if the health monitor has been passed in, it exists on the system already
    if slb_health_monitor:
        result_hm = axapi_call_v3(module, axapi_base_url + 'health/monitor/' + slb_health_monitor)
        if ('response' in result_hm and result_hm['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error            
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result_hm['response']['err']['msg'])

 
    # then we check to see if the specified service group exists
    result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method="GET", signature=signature)    
    if ('response' in result and result['response']['status'] == 'fail'):
        if (result['response']['code'] == 404):
            slb_service_group_exist = False
        else:
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])
    else:
#        sg_content = result['response']['data']
        slb_service_group_exist = True
    
    # clear the 'changed' flag
    changed = False
        
    if state == 'present':
        # before creating/updating we need to validate that servers
        # defined in the servers list exist to prevent errors
        server_exist = True
        for server in slb_servers:
            result = axapi_call_v3(module, axapi_base_url + 'slb/server/' + server['name'], method="GET", signature=signature)
            
            # did the lookup of the server return some error
            if ('response' in result and result['response']['status'] == 'fail'):
                if (result['response']['code'] == 404):
                    server_exist = False
                    break
                else:
                    logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                    module.fail_json(msg=result['response']['err']['msg'])

            # add server to the member-list
            json_post['service-group']['member-list'].append(server)                    
                    
        if not server_exist:
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg="server %s does not exist" % server['name'])
                

        if slb_service_group_exist and not overwrite:
            # just exit gracefully with a message
            msg='service-group exists but not modified'
            
        elif slb_service_group_exist and overwrite:
            # overwrite the properties of the service group
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method="PUT", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "service group %s updated" % slb_service_group
            
        elif not slb_service_group_exist:
            # create a new server
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/', method="POST", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "service-group %s created" % slb_server
            
    elif state == 'absent':
        if slb_service_group_exist:
            result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + slb_service_group, method="DELETE", signature=signature)
            changed = True
        else:
            result = dict(msg="the service group was not present")

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
    module.exit_json(changed=changed, content=result, msg=msg)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *
import codecs

if __name__ == '__main__':
    main()
