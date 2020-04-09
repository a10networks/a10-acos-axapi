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
module: a10_tcp_template
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage tcp template objects on A10 Networks devices via aXAPI
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
      - L3V partition to add the template to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create, update or remove tcp template
    required: false
    default: present
    choices: ['present', 'absent']
  name:
    description:
      - name of the template
    required: true
  alive_if_active:
    description:
      - terminates half-open tcp sessions on a vPort while allowing active sessions to continue
    required: false
    default: null
  idle_timeout:
    description:
      - number of secs a connection can remain idle before ACOS terminates it
    required: false
    default: null
  force_del_timeout_unit:
    description:
      - force delete timeout unit
        0 = seconds
        1 = 100ms
    required: false
    default: 0
    choices: [0, 1]
  force_del_timeout:
    description:
      - max number of seconds a session can remain active
        range 1-31
    required: false
    default: 0
  init_win_size:
    description:
      - set initial tcp window size in SYN ACK packets to clients
        range 1-65535
    required: false
    default: 0
  half_close_idle_timeout:
    description:
      - enable aging of half-closed TCP sessions
        range 60-15000
    required: false
    default: 0
  reset_fwd:
    description:
      - sends a TCP RST to the real server after a session times out
    required: false
    default: false
    choices: [true, false]
  reset_rec:
    description:
      - sends a TCP RST to the client after a session times out
    required: false
    default: false
    choices: [true, false]
  fast_tcp_acl_on_lan:
    description:
      - increases performance of bidirectional peer sessions by acknowledging receipt of data on behalf of client servers
    required: false
    default: false
    choices: [true, false]
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
# Create a new TCP Template
- a10_tcp_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_tcp_templ
    force_del_timeout: true
    init_win_size: 32768
    reset_fwd: true
    reset_rec: true

'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            alive_if_active=dict(type='bool', default=False),
            idle_timeout=dict(type='int', default=120),
            force_del_timeout_unit=dict(type='int', default=0),
            force_del_timeout=dict(type='int', default=0),
            init_win_size=dict(type='int', default=0),
            half_close_idle_timeout=dict(type='int', default=False),
            reset_fwd=dict(type='bool', default=False),
            reset_rec=dict(type='bool', default=False),
            fast_tcp_acl_on_lan=dict(type='bool', default=False),
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

    alive_if_active = module.params['alive_if_active']
    idle_timeout = module.params['idle_timeout']
    force_del_timeout_unit = module.params['force_del_timeout_unit']
    force_del_timeout = module.params['force_del_timeout']
    init_win_size = module.params['init_win_size']
    half_close_idle_timeout = module.params['half_close_idle_timeout']
    reset_fwd = module.params['reset_fwd']
    reset_rec = module.params['reset_rec']
    fast_tcp_acl_on_lan = module.params['fast_tcp_acl_on_lan']

    if name is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])


    # populate the json body for the creation of the tcp template
    json_post = {
        'tcp_template': {
            'name': name,
        }
    }

    if alive_if_active is None or alive_if_active == False:
        json_post['tcp_template']['alive_if_active'] = 0
    else:
        json_post['tcp_template']['alive_if_active'] = 1

    if idle_timeout is not None:
        json_post['tcp_template']['idle_timeout'] = idle_timeout

    if force_del_timeout_unit is None or force_del_timeout_unit == False:
        json_post['tcp_template']['force_del_timeout_unit'] = 0
    else:
        json_post['tcp_template']['force_del_timeout_unit'] = 1

    if force_del_timeout is None or force_del_timeout == False:
        json_post['tcp_template']['force_del_timeout'] = 0
    else:
        json_post['tcp_template']['force_del_timeout'] = 1

    if init_win_size is not None:
        json_post['tcp_template']['init_win_size'] = init_win_size

    if half_close_idle_timeout is not None or half_close_idle_timeout == False:
        json_post['tcp_template']['half_close_idle_timeout'] = 0
    else:
        json_post['tcp_template']['half_close_idle_timeout'] = 1

    if reset_fwd is None or reset_fwd == False:
        json_post['tcp_template']['reset_fwd'] = 0
    else:
        json_post['tcp_template']['reset_fwd'] = 1

    if reset_rec is None or reset_rec == False:
        json_post['tcp_template']['reset_rec'] = 0
    else:
        json_post['tcp_template']['reset_rec'] = 1

    if fast_tcp_acl_on_lan is None or fast_tcp_acl_on_lan == False:
        json_post['tcp_template']['fast_tcp_acl_on_lan'] = 0
    else:
        json_post['tcp_template']['fast_tcp_acl_on_lan'] = 0
    
    
    # check to see if this tcp_template exists
    tcp_template_data = axapi_call(module, session_url + '&method=slb.template.tcp.search', json.dumps({'name': name}))
    tcp_template_exists = not axapi_failure(tcp_template_data)

    changed = False
    if state == 'present':

        if not tcp_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.tcp.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the tcp template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.tcp.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the tcp template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if tcp_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.tcp.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the tcp template was not present")

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
