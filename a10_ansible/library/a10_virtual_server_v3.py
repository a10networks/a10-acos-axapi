#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb virtual server objects
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
module: a10_virtual_server
version_added: 1.8
short_description: Manage A10 Networks devices' virtual servers
description:
    - Manage slb virtual server objects on A10 Networks devices via aXAPI
author: "Fadi Hafez (@a10-fhafez)"
notes:
    - Requires A10 Networks aXAPI 2.1
requirements: []
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
  virtual_server:
    description:
      - slb virtual server name
    required: true
    default: null
    aliases: ['vip', 'virtual']
    choices: []
  virtual_server_ip:
    description:
      - slb virtual server ip address
    required: false
    default: null
    aliases: ['ip', 'address']
    choices: []
  virtual_server_status:
    description:
      - slb virtual server status
    required: false
    default: enable
    aliases: ['status']
    choices: ['enabled', 'disabled']
  acl_id:
    description:
      - acl bound to the virtual server, used for wild card vips
    required: false
    default: null
    aliases: ['acl_id']
  acl_name:
    description:
      - acl name bound to the ipv6 virtual server, used for ipv6 wild card vips
    required: false
    default: null
  disable_vserver_on_condition:
    description:
      - disable VIP on
        0 means never
        1 means when_any_port_down
        2 means when_all_ports_down
    required: false
    default: 0
  redistribution_flagged:
    description:
      - flag this VIP for redistribution through routing protocols
    required: false
    default: False
    choices: ['True','False']
  virtual_server_ports:
    description:
      - A list of ports to create for the virtual server. Each list item should be a
        dictionary which specifies the C(port:) and C(type:), but can also optionally
        specify the C(service_group:) as well as the C(status:). See the examples
        below for details. This parameter is required when C(state) is C(present).
    required: false
  overwrite:
    description:
      - If the VS is found, should you overwrite or just ignore it
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
# Create a new virtual server
- a10_virtual_server: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver1
    virtual_server_ip: 1.1.1.1
    virtual_server_ports:
      - port: 80
        protocol: TCP
        service_group: sg-80-tcp
      - port: 443
        protocol: HTTPS
        service_group: sg-443-https
      - port: 8080
        protocol: http
        status: disabled

# Create a new wild card virtual server
- a10_virtual_server: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver2
    virtual_server_ip: 0.0.0.0
    acl_id: 101
    virtual_server_ports:
      - port: 443
        protocol: HTTPS
        service_group: sg-443-https

# Create a new IPv6 wild card virtual server
- a10_virtual_server: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_DEMO
    virtual_server: vserver_v6
    virtual_server_ip: 0::0
    acl_name: v6_acl
    virtual_server_ports:
      - port: 443
        protocol: HTTPS
        service_group: sg-v6-443-https



'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part']), 
            virtual_server=dict(type='str', aliases=['vip', 'virtual'], required=True),
            virtual_server_ip=dict(type='str', aliases=['ip', 'address'], required=True),
            virtual_server_status=dict(type='str', default='enabled', aliases=['status'], choices=['enabled', 'disabled']),
            disable_vserver_on_condition=dict(type='str', choices=['enable','disable','disable-when-all-ports-down', 'disable-when-any-port-down'], required=False, default='enable'),
            redistribution_flagged=dict(type='str', choices=['True','False'], required=False, default='False'),
            acl_id=dict(type='str', required=False, default=None),
            acl_name=dict(type='str', required=False, default=None),
            virtual_server_ports=dict(type='list', required=True),
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
    slb_virtual = module.params['virtual_server']
    slb_virtual_ip = module.params['virtual_server_ip']
    slb_virtual_status = module.params['virtual_server_status']
    slb_virtual_ports = module.params['virtual_server_ports']
    redistribution_flagged = module.params['redistribution_flagged']
    acl_id = module.params['acl_id']
    acl_name = module.params['acl_name']
    disable_vserver_on_condition = module.params['disable_vserver_on_condition']
    overwrite = module.params['overwrite']    

    # check mandatory fields
    if slb_virtual is None:
        module.fail_json(msg='virtual_server is required')

    axapi_base_url = 'http://%s/axapi/v3/' % host

    # first we authenticate to get a session id
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)
    
    # change partitions if we need to
    if part:
        result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error            
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])

    json_post = {
        'virtual-server': {
            'name': slb_virtual,
            'status': axapi_enabled_disabled(slb_virtual_status),
            'port-list': slb_virtual_ports,
            'enable-disable-action': disable_vserver_on_condition,
            'redistribution-flagged': redistribution_flagged,
        }
    }
    
    # if acl id or acl name was passed in bind it to the vip, otherwise assign the ip address passed in
    if acl_id or acl_name:
        if acl_id:
            json_post['virtual-server']['acl-id'] = acl_id
        else:
            json_post['virtual-server']['acl-name'] = acl_name
    else:
        json_post['virtual-server']['ip-address'] = slb_virtual_ip
    

    result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual, method="GET", signature=signature)    

    if ('response' in result and result['response']['status'] == 'fail'):
        if (result['response']['code'] == 404):
            slb_virtual_exists = False
        else:
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=result['response']['err']['msg'])
    else:
        slb_virtual_exists = True
    
    # clear the 'changed' flag
    changed = False
    
    if state == 'present':
        # before creating/updating we need to validate that all
        # service groups defined in the ports list exist
        checked_service_groups = []
        for port in slb_virtual_ports:
            if 'service-group' in port:
                # validate that the service group exists already                
                result = axapi_call_v3(module, axapi_base_url + 'slb/service-group/' + port['service-group'], method="GET", signature=signature)

                # did the lookup of the service-group return some error
                if ('response' in result and result['response']['status'] == 'fail'):
                    if (result['response']['code'] == 404):
                        sg_exist = False
                        break
                    else:
                        logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                        module.fail_json(msg=result['response']['err']['msg'])

                # add port to the port-list
                json_post['virtual-server']['port-list'].append(port)                    

        if slb_virtual_exists and not overwrite:
            msg = 'virtual server exists but not modified'
            
        elif slb_virtual_exists and overwrite:
            # overwrite the properties of the virtual server
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual, method="PUT", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "virtual server %s updated" % slb_virtual

        elif not slb_virtual_exists:
            # create a new server
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/', method="POST", signature=signature, body=json_post)
            if ('response' in result and 'err' in result['response']):
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg=result['response']['err']['msg'])
            
            changed = True
            msg = "virtual server %s created" % slb_server
        
    elif state == 'absent':
        if slb_virtual_exists:
            result = axapi_call_v3(module, axapi_base_url + 'slb/virtual-server/' + slb_virtual, method="DELETE", signature=signature)
            changed = True
        else:
            result = dict(msg="the virtual server was not present")

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
if __name__ == '__main__':
    main()
