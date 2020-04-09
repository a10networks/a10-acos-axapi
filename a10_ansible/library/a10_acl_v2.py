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
module: a10_acl
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage extended acl objects on A10 Networks devices via aXAPI
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
      - create, update or remove acl
    required: false
    default: present
    choices: ['present', 'absent']
  acl_id:
    description:
      - acl ID (100 - 199)
    required: true
    aliases: ['acl']
  remark_list:
    description:
      - List of remarks
        Must contain a list of seq_num and remark_string pairs
    required: false
    default: null
    aliases: ['rem']
  item_list:
    description:
      - List of extended ACL items
        Must contain seq_num (range 1 - 8192)
        Can contain 
          - action (0=deny,1=permit,2=l3-vlan-fwd-disable, default:0), 
            log (0=deny,1=permit,2=only log transparent sessions, default:0),
            protocol (0=icmp,1=ip,2=tcp,3=udp, default:0)
            src_ip, 
            src_mask,
            dst_ip,
            dst_mask,
            vlan_id,
            src_port_start,
            src_port_end,
            dst_port_start,
            dst_port_end
    required: true
    aliases: ['items']
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
# Create a new acl
- a10_acl: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    acl_id: 100
    remark_list:
      - seq_num: 12
        remark_string: "something to allow"
      - seq_num: 16
        remark_string: "something to block"
    acl_item_list:
      - seq_num: 1
        action: 1
        log: 1
        protocol: 2
        src_ip: "0.0.0.0"
        src_mask: "255.255.255.255"
        dst_ip: "0.0.0.0"
        dst_mask: "255.255.255.255"
        vlan_id: 0

'''

VALID_ACL_REM_FIELDS = ['seq_num', 'remark_string']
VALID_ACL_LIST_FIELDS = ['seq_num','action','log','protocol','src_ip','src_mask','dst_ip','dst_mask','vlan_id','name','dst_port_start','dst_port_end','src_port_start','src_port_end']

def validate_keys(module, rem_or_list, keys):
    if (rem_or_list == 'rem'):
        VALID_FIELDS = VALID_ACL_REM_FIELDS
    else:
        VALID_FIELDS = VALID_ACL_LIST_FIELDS

    for item in keys:
        for key in item:
            if key not in VALID_FIELDS:
                module.fail_json(msg="invalid field (%s), must be one of: %s" % (key, ','.join(VALID_FIELDS)))


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            acl_id=dict(type='int', aliases=['id'], required=True),
            remark_list=dict(type='list', aliases=['rem'], default=[]),
            acl_item_list=dict(type='list', aliases=['acl'], default=[]),
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
    acl_id = module.params['acl_id']
    acl_remarks = module.params['remark_list']
    acl_items = module.params['acl_item_list']

    if acl_id is None:
        module.fail_json(msg='acl id is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

    # validate the ports data structure
    validate_keys(module, 'rem', acl_remarks)
    validate_keys(module, 'items', acl_items)

    json_post = {
        'ext_acl': {
            'id': acl_id,
            'acl_item_list': acl_items,
        }
    }

    if acl_remarks and len(acl_remarks) > 0:
        json_post['ext_acl']['remark_list'] = acl_remarks

    acl_data = axapi_call(module, session_url + '&method=network.acl.ext.search', json.dumps({'id': acl_id}))
    acl_exists = not axapi_failure(acl_data)

    changed = False
    if state == 'present':

        if not acl_exists:
            result = axapi_call(module, session_url + '&method=network.acl.ext.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the acl: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=network.acl.ext.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the acl: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if acl_exists:
            result = axapi_call(module, session_url + '&method=network.acl.ext.delete', json.dumps({'id': acl_id}))
            changed = True
        else:
            result = dict(msg="the acl was not present")

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
