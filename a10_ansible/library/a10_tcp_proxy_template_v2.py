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
    - Manage tcp proxy template objects on A10 Networks devices via aXAPI
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
  fin_timeout:
    description:
      - Specify number of seconds a connection can be in the FIN-WAIT or CLOSING state before ACOS terminates.
        Range is 1 to 60
    required: false
    default: 5
  idle_timeout:
    description:
      - Specify number of minutes a connection can be idle before ACOS terminates connection.
        Range is 60 to 2097151
    required: false
    default: 600
  force_del_timeout_unit:
    description:
      - Specify force delete timeout unit.
        0 is seconds, 1 is 100ms
    required: false
    default: 0
    choices: [0, 1]
  force_del_timeout:
    description:
      - Specify maximum number of seconds a session can remain active, and forces deletion of any session that is still active after specified number of seconds.
        Range is 1 to 31
    required: false
    default: 0
  alive_if_active:
    description:
      - keep alive if active
    required: false
    default: 0
    choices: [0, 1]
  half_close_idle_timeout:
    description:
      - Enables aging of halfl-closed TCP sessions.
        Range is 60 to 15000
    required: false
    default: 0
  half_open_idle_timeout:
    description:
      - Enables aging of halfl-open TCP sessions.
        Range is 60 to 15000
    required: false
    default: 0
  retransmit_retries:
    description:
      - retransmits
        Range is 1 to 20
    required: false
    default: 3
  syn_retries:
    description:
      - SYN retries
        Range is 1 to 20
    required: false
    default: 5
  time_wait:
    description:
      - keeping connections in TIME WAIT state
        Range is 1 to 60
    required: false
    default: 5
  receive_buffer:
    description:
      - Receive buffer in bytes.
        Range is 1 to 2147483647
    required: false
    default: 51200
  transmit_buffer:
    description:
      - Transmit buffer in bytes.
        Range is 1 to 2147483647
    required: false
    default: 51200
  nagle:
    description:
      - Enable Nagle congestion compression.
    required: false
    default: 0
    choices: [0, 1]
  init_window_size:
    description:
      - Set intial TCP window size in SYN ACK packets to clients.
        Range is 1 to 65535
    required: false
    default: 0
  back_win_sca:
    description:
      - Specify TCP window scaling factor for backend connections to servers.
        Range is 1 to 14
    required: false
    default: 0
  mss:
    description:
      - Change the minimum supported TCP Maximum Segment Size.
        Range is 128 to 4312
    required: false
    default: 1460
  keep_alive_probes:
    description:
      - Maximum number of times ACOS sends a keepalive, ACK before deleting the session.
        Range is 2 to 10
    required: false
    default: 0
  keep_alive_interval:
    description:
      - Number of seconds a TCP-proxy session remains idle before ACOS sends a TCP ACK to the devices on both ends of a session.
        Range is 60 to 12000
    required: false
    default: 0
  reno:
    description:
      - Enables TCP Reno congestion control algorithm, and disables
    required: false
    default: 0
    choices: [0, 1]
  dyn_buf_alloc:
    description:
      - Conctact A10 Networks
    required: false
    default: 0
    choices: [0, 1]
  reset_fwd:
    description:
      - Sends a TCP RST to the real server after a session times out.
    required: false
    default: 0
    choices: [0, 1]
  reset_rev:
    description:
      - Sends a TCP RST to the the client after a session times out
    required: false
    default: 0
    choices: [0, 1]
  initial_cwnd:
    description:
      - Specify maximum number of unacknowledged packets that can be sent on a TCP connection.
        Range is 1 to 10
    required: false
    default: 4
  ack_aggr:
    description:
      - Specify which cases ACOS sends an ACK to the client.
        Range is 0 - 3
        0 is low, 1 is medium, 2 is high
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
# Create a new TCP Template
- a10_tcp_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_tcp_proxy_templ
    reno: 1
    idle_timeout: 1200
    reset_fwd: 1
    reset_rev: 1

'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            fin_timeout=dict(type='int', required=False),
            idle_timeout=dict(type='int', required=False),
            force_del_timeout_unit=dict(type='int', required=False),
            force_del_timeout=dict(type='int', required=False),
            alive_if_active=dict(type='bool', required=False),
            half_close_idle_timeout=dict(type='int', required=False),
            half_open_idle_timeout=dict(type='int', required=False),
            retransmit_retries=dict(type='int', required=False),
            syn_retries=dict(type='int', required=False),
            time_wait=dict(type='int', required=False),
            receive_buffer=dict(type='int', required=False),
            transmit_buffer=dict(type='int', required=False),
            nagle=dict(type='bool', required=False),
            init_window_size=dict(type='int', required=False),
            back_win_sca=dict(type='int', required=False),
            mss=dict(type='int', required=False),
            keep_alive_probes=dict(type='int', required=False),
            keep_alive_interval=dict(type='int', required=False),
            reno=dict(type='bool', required=False),
            dyn_buf_alloc=dict(type='bool', required=False),
            reset_fwd=dict(type='bool', required=False),
            reset_rev=dict(type='bool', required=False),
            initial_cwnd=dict(type='int', required=False),
            ack_aggr=dict(type='int', required=False),
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

    # create a dict of the possible parameters for a tcp_proxy
    param_names = [
        "name",
        "fin_timeout",
        "idle_timeout",
        "force_del_timeout_unit",
        "force_del_timeout",
        "alive_if_active",
        "half_close_idle_timeout",
        "half_open_idle_timeout",
        "retransmit_retries",
        "syn_retries",
        "time_wait",
        "receive_buffer",
        "transmit_buffer",
        "nagle",
        "init_window_size",
        "back_win_sca",
        "mss",
        "keep_alive_probes",
        "keep_alive_interval",
        "reno",
        "dyn_buf_alloc",
        "reset_fwd",
        "reset_rev",
        "initial_cwnd",
        "ack_aggr"]


    # put the parameters that were passed in into a dictionary
    params = {}
    for curr_param_name in param_names:
        params[curr_param_name] =  module.params[curr_param_name]

    # tcp_proxy name is mandatory
    if params['name'] is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])


    # populate the json body for the creation of the tcp proxy template
    json_post = {
        "tcp_proxy_template": {
            "name": "tcpproxytempl"
            ,"fin_timeout": 5
            ,"idle_timeout": 600
            ,"force_del_timeout_unit": 0
            ,"force_del_timeout": 0
            ,"alive_if_active": 0
            ,"half_close_idle_timeout": 0
            ,"retransmit_retries": 3
            ,"half_open_idle_timeout": 0
            ,"time_wait": 5
            ,"receive_buffer": 51200
            ,"transmit_buffer": 51200
            ,"nagle": 0
            ,"init_window_size": 0
            ,"back_win_sca": 0
            ,"mss": 1460
            ,"keep_alive_probes": 0
            ,"keep_alive_interval": 0
            ,"reno": 0
            ,"dyn_buf_alloc": 0
            ,"reset_fwd": 0
            ,"reset_rev": 0
            ,"initial_cwnd": 4
            ,"ack_aggr": 0
            ,"syn_retries": 5
        }
    }


    # modify the json body with only the parameters that have been passed in
    for pn in param_names:
        if params[pn]:
            if type(params[pn]) is bool and params[pn] == True or params[pn] == "true":
                json_post['tcp_proxy_template'][pn] = 1
            elif type(params[pn]) is bool and params[pn] == False:
                json_post['tcp_proxy_template'][pn] = 0
            else:
                json_post['tcp_proxy_template'][pn] = params[pn]
   
    
    # check to see if this tcp_proxy_template exists
    tcp_proxy_template_data = axapi_call(module, session_url + '&method=slb.template.tcp_proxy.search', json.dumps({'name': params['name']}))
    tcp_proxy_template_exists = not axapi_failure(tcp_proxy_template_data)

    changed = False
    if state == 'present':

        if not tcp_proxy_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.tcp_proxy.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the tcp proxy template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.tcp_proxy.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the tcp proxy template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if tcp_proxy_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.tcp_proxy.delete', json.dumps({'name': params['name']}))
            changed = True
        else:
            result = dict(msg="the tcp proxy template was not present")

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
