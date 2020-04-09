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
module: a10_src_ip_persistence_template
version_added: 2.2.0.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage src ip persistence template objects on A10 Networks devices via aXAPI
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
      - create, update or remove template
    required: false
    default: present
    choices: ['present', 'absent']
  name:
    description:
      - name of the template
    required: true
  match_type:
    description:
      - specify granluarity of persistence
      - 0 = port
      - 1 = server
      - 2 = service group
    required: false
    default: 0
  match_all:
    description:
      - scan all members bound to the template
      - only available when match_type is 1 or 2
    required: false
    default: 0
  timeout:
    description:
      - how many minutes the mapping remains persistent after the last time traffic from the client was sent to thes server
      - range is 1 to 2000
    required: false
    default: 5
  no_honor_conn:
    description:
      - ignore connection limit settings configured on real servers and real ports
    required: false
    choices: ["yes", "no"]
    default: 0
  incl_sport:
    description:
      - include the source port in persistent sessions
    required: false
    default: 0
    choices: ["yes", "no"]
  include_dstip:
    description:
      - supports the ALG protocol firewall load balancing feature for protocols such as FTP
    required: false
    choices: ["yes", "no"]
    default: 0
  hash_persist:
    description:
      - enable hash-based persistence
    required: false
    choices: ["yes", "no"]
    default: 0
  enforce_high_priority:
    description:
      - enable Source-IP Persistence Override and Reselect
    required: false
    choices: ["yes", "no"]
    default: 0
  netmask:
    description:
      - specify granularity of IP address hashing for serport selection. IPv4 address in dotted decimal form
    required: false
    default: 255.255.255.255
  netmask6:
    description:
      - specify granularity of IPv6 address hashing for initial server port selection
    required: false
    default: 128
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
    version_added: 2.2.0.0
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new SRC IP Persistence Template
- a10_src_ip_persistence_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_src_ip_pers_templ
    match_type: 1
    timeout: 20

'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            match_type=dict(type='str', default=None),
            match_all=dict(type='str', default=None),
            timeout=dict(type='int', default=0),
            no_honor_conn=dict(type='bool', default=False),
            incl_sport=dict(type='bool', default=False),
            include_dstip=dict(type='bool', default=False),
            hash_persist=dict(type='bool', default=False),
            enforce_high_priority=dict(type='bool', default=False),
            netmask=dict(type='str', default='255.255.255.255'),
            netmask6=dict(type='int', default=128),
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

    match_type = module.params['match_type']
    match_all = module.params['match_all']
    timeout = module.params['timeout']
    no_honor_conn = module.params['no_honor_conn']
    incl_sport = module.params['incl_sport']
    include_dstip = module.params['include_dstip']
    hash_persist = module.params['hash_persist']
    enforce_high_priority = module.params['enforce_high_priority']
    netmask = module.params['netmask']
    netmask6 = module.params['netmask6']

    if name is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    # populate the json body for the creation of the http template
    json_post = {
        'src_ip_persistence_template': {
            'name': name,
        }
    }

    if match_type:
        json_post['match_type'] = match_type

    if match_all:
        json_post['match_all'] = match_all

    if timeout:
        json_post['timeout'] = timeout

    if no_honor_conn:
        json_post['no_honor_conn'] = no_honor_conn

    if incl_sport:
        json_post['incl_sport'] = incl_sport

    if include_dstip:
        json_post['include_dstip'] = include_dstip
   
    if hash_persist:
        json_post['hash_persist'] = hash_persist

    if enforce_high_priority:
        json_post['enforce_high_priority'] = enforce_high_priority

    if netmask:
        json_post['netmask'] = netmask

    if netmask6:
        json_post['netmask6'] = netmask6


    # check to see if this src ip persistence template exists
    src_ip_persistence_template_data = axapi_call(module, session_url + '&method=slb.template.src_ip_persistence.search', json.dumps({'name': name}))
    src_ip_persistence_template_exists = not axapi_failure(src_ip_persistence_template_data)

    changed = False
    if state == 'present':

        if not src_ip_persistence_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.src_ip_persistence.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the src ip persistence template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.src_ip_persistence.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the src ip persistence template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if src_ip_persistence_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.src_ip_persistence.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the src ip persistence template was not present")

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
