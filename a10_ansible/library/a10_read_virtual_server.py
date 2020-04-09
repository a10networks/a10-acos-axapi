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
module: a10_read_virtual_server
version_added: 1.0
short_description: Check A10 Networks devices' virtual servers
description:
    - Check slb virtual server objects on A10 Networks devices via aXAPI
author: "Fadi Hafez"
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
  partition:
    description:
      - L3V partition to look for the Virtual Server
    required: false
    default: null
    choices: []
  virtual_server:
    description:
      - slb virtual server name
    required: false
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
- a10_read_virtual_server: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_PRV
    virtual_server: vserver1
    virtual_server_ip: 1.1.1.1
'''

VALID_PORT_FIELDS = ['port', 'protocol', 'service_group', 'status']

def validate_ports(module, ports):
    for item in ports:
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port' in item:
            try:
                item['port'] = int(item['port'])
            except:
                module.fail_json(msg="port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port field")

        # validate the port protocol is present, and convert it to
        # the internal API integer value (and validate it)
        if 'protocol' in item:
            protocol = axapi_get_vport_protocol(item['protocol'])
            if not protocol:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_VPORT_PROTOCOLS))
            else:
                item['protocol'] = protocol
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_VPORT_PROTOCOLS))

        # convert the status to the internal API integer value
        if 'status' in item:
            item['status'] = axapi_enabled_disabled(item['status'])
        else:
            item['status'] = 1

        # ensure the service_group field is at least present
        if 'service_group' not in item:
            item['service_group'] = ''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part']), 
            virtual_server=dict(type='str', aliases=['vip', 'virtual'], required=False),
            virtual_server_ip=dict(type='str', aliases=['ip', 'address'], required=False),
            username=dict(type='str', aliases=['user']), 
            password=dict(type='str', aliases=['pass']), 
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
    

    slb_virtual = module.params['virtual_server']
    slb_virtual_ip = module.params['virtual_server_ip']

#    validate_ports(module, slb_virtual_ports)

    axapi_base_url = 'https://%s/services/rest/V2/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if a partition has been provided
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active',
                                            json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    # if the user provided the vs_name then search on that
    # otherwise if the user provided the vs_address then search on that
    # otherwise just get all virtual servers
    if slb_virtual:
        slb_virtual_data = axapi_call(module, session_url + '&method=slb.virtual_server.search', json.dumps({'name': slb_virtual}))
        slb_virtual_exists = not axapi_failure(slb_virtual_data)

    elif slb_virtual_ip:
        slb_virtual_data = axapi_call(module, session_url + '&method=slb.virtual_server.search', json.dumps({'address': slb_virtual_ip}))
        slb_virtual_exists = not axapi_failure(slb_virtual_data)

    else:
        slb_virtual_data = axapi_call(module, session_url + '&method=slb.virtual_server.getAll')
        slb_virtual_exists = not axapi_failure(slb_virtual_data)

    if not slb_virtual_exists:
        module.fail_json(msg="failed to find the virtual server: %s" % slb_virtual_data['response']['err']['msg'])

    else:
        defined_ports = slb_virtual_data.get('virtual_server_list', {})
#        print "response: " + defined_ports
#        display = Display()
#        display.display(str(slb_virtual_data['virtual_server_list']), color='green')

    result = None

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=False, output=defined_ports)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *
from ansible.utils.display import Display
if __name__ == '__main__':
    main()
