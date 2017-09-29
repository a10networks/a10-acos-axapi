#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>,
2016, Eric Chou <ericc@a10networks.com>

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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: a10_server
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' server object.
description:
    - Manage SLB (Server Load Balancer) server objects on A10 Networks devices via aXAPIv2.
author: "Eric Chou (@ericchou) 2016, Mischa Peters (@mischapeters) 2014"
notes:
    - Requires A10 Networks aXAPI 2.1.
extends_documentation_fragment: a10
options:
  partition:
    version_added: "2.3"
    description:
      - set active-partition
    required: false
    default: null
  server_name:
    description:
      - The SLB (Server Load Balancer) server name.
    required: true
    aliases: ['server']
  server_ip:
    description:
      - The SLB server IPv4 address.
    required: false
    default: null
    aliases: ['ip', 'address']
  server_status:
    description:
      - The SLB virtual server status.
    required: false
    default: enabled
    aliases: ['status']
    choices: ['enabled', 'disabled']
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a
        dictionary which specifies the C(port:) and C(protocol:), but can also optionally
        specify the C(status:). See the examples below for details. This parameter is
        required when C(state) is C(present).
    required: false
    default: null
  state:
    description:
      - This is to specify the operation to create, update or remove SLB server.
    required: false
    default: present
    choices: ['present', 'absent']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.3
    default: 'yes'
    choices: ['yes', 'no']

'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new server
- a10_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: mypartition
    server: test
    server_ip: 1.1.1.100
    server_ports:
      - port_num: 8080
        protocol: tcp
      - port_num: 8443
        protocol: TCP

'''

RETURN = '''
content:
  description: the full info regarding the slb_server
  returned: success
  type: string
  sample: "mynewserver"
'''

def 

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),

            server_status=dict(type='str', default='enabled', aliases=['status'], choices=['enabled', 'disabled']),
            server_ports=dict(type='list', aliases=['port'], default=[]),
            server_conn_limit=dict(type='str', aliases=['conn-limit'], default="8000000"),
            server_weight=dict(type='str', aliases=['weight'], default="1"),

        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    partition = module.params['partition']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    write_config = module.params['write_config']
    server_name = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_status = module.params['server_status']
    slb_server_ports = module.params['server_ports']

    if slb_server is None:
        module.fail_json(msg='server_name is required')

    acos_clien = acos.Client(host, '3.0', username, password)

    changed = False
    try:
        if state == "absent":
            try:
                result = acos_client.slb.server.delete(server_name)
            except acos_errors.NotFound:
                result = "server does not exist"
        else if state == "present":
            slb_server = get_server()
            if slb_server:
                update = check_update_server()
                if update:
                    update_ports = check_update_ports()
                    if update_ports:
                        result = acos_client.slb.server.update(server_name, server_args)
                    else:
                        result = acos_client.slb.server.update(server_name, server_args)
            else:
                result = acos_client.slb.server.create(server_name, server_args)
    except Exception as e:
        module.fail_json(msg=("Caught exception: {0}").format(server_name))

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.a10 import axapi_call, a10_argument_spec, axapi_authenticate, axapi_failure
from ansible.module_utils.a10 import axapi_get_port_protocol, axapi_enabled_disabled, AXAPI_PORT_PROTOCOLS

if __name__ == '__main__':
    main()
