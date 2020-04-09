#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks objects
(c) 2016, Fadi Hafez <fhafez@a10networks.com>

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
module: a10_nat_pool
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage extended nat pool objects on A10 Networks devices via aXAPI
author: Fadi Hafez using works of Mischa Peters
notes:
    - Requires A10 Networks aXAPI 2.1
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
      - L3V partition to add the ACL to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create, update or remove nat pool
    required: false
    default: present
    choices: ['present', 'absent']
  name:
    description:
      - name of pool
    required: true
  start_ip_addr:
    description:
      - first ip address of the pool
    required: true
  end_ip_addr:
    description:
      - last ip address of the pool
    required: true
  netmask:
    description:
      - netmask for the pool
    required: false
    default: ""
  gateway:
    description:
      - gateway of the pool
    required: false
    default: "0.0.0.0"
  ha_group_id:
    description:
      - when HA is enabled.  Range is 0 to 31
    required: false
    default: 0
  ip_rr:
    description:
      - use IP address round-robin behavior
    required: false
    default: 0
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: "no"
    choices: ["yes", "no"]
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
# Create a new nat pool
- a10_nat_pool_v2: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: natpool
    start_ip_addr: 10.0.0.1
    end_ip_addr: 10.0.0.2
    netmask: 255.255.255.255

'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', aliases=['id'], required=True),
            start_ip_addr=dict(type='str', required=True),
            end_ip_addr=dict(type='str', required=True),
            netmask=dict(type='str', required=True),
            gateway=dict(type='str', required=False, default="0.0.0.0"),
            ha_group_id=dict(type='int', required=False, default=0),
            ip_rr=dict(type='int', required=False, default=0),
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
    name = module.params['name']
    start_ip_addr = module.params['start_ip_addr']
    end_ip_addr = module.params['end_ip_addr']
    netmask = module.params['netmask']
    gateway = module.params['gateway']
    ha_group_id = module.params['ha_group_id']
    ip_rr = module.params['ip_rr']

    if name is None:
        module.fail_json(msg='nat pool id is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    json_post = {
        'pool': {
            'name': name,
            'start_ip_addr': start_ip_addr,
            'end_ip_addr': end_ip_addr,
            'netmask': netmask,
        }
    }

    if len(gateway) > 0:
        json_post['pool']['gateway'] = gateway

    if ha_group_id > 0:
        json_post['pool']['ha_group_id'] = ha_group_id

    if ip_rr > 0:
        json_post['pool']['ip_rr'] = ip_rr

    natpool_data = axapi_call(module, session_url + '&method=nat.pool.search', json.dumps({'name': name}))
    natpool_exists = not axapi_failure(natpool_data)

    changed = False
    if state == 'present':

        if not natpool_exists:
            result = axapi_call(module, session_url + '&method=nat.pool.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the nat pool: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=nat.pool.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the nat pool: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if natpool_exists:
            result = axapi_call(module, session_url + '&method=nat.pool.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the nat pool was not present")

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *

if __name__ == '__main__':
    main()
