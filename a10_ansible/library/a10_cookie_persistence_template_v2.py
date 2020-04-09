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
module: a10_cookie_persistence_template
version_added: 2.2.0.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage cookie persistence template objects on A10 Networks devices via aXAPI
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
  expire_exist:
    description:
      - does it expire
    required: false
    choices: ["yes", "no"]
    default: 0
  expire:
    description:
      - when does it expire
      - 0 to 31536000
    required: false
    default: 0
  cookie_name:
    description:
      - name of the cookie
      - length is 0 to 63 characters
    required: false
    default: None
  domain:
    description:
      - domain name
      - length is 0 to 31 characters
    required: false
    default: 0
  path:
    description:
      - path of the cookie
      - length is 0 to 31 characters
    required: false
    default: 0
  match_type:
    description:
      - 0=port, 1=server, 2=service group
    required: false
    choices: [0,1,2]
    default: 0
  match_all:
    description:
      - scans all members bound to the template
    required: false
    choices: ["yes", "no"]
    default: 0
  insert_always:
    description:
      - insert even if it exists already
    required: false
    choices: ["yes", "no"]
    default: 0
  dont_honor_conn:
    description:
      - dont honor connection
    required: false
    choices: ["yes", "no"]
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
    version_added: 2.2.0.0
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new SRC IP Persistence Template
- a10_cookie_persistence_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_cookie_pers_templ
    match_type: 1
    cookie_name: testcookie

'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            match_type=dict(type='int', default=0),
            match_all=dict(type='bool', default=False),
            expire_exist=dict(type='bool', default=False),
            expire=dict(type='int', default=False),
            cookie_name=dict(type='str', default=""),
            domain=dict(type='str', default=""),
            path=dict(type='str', default=""),
            insert_always=dict(type='bool', default=False),
            dont_honor_conn=dict(type='bool', default=False),
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

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # create a list of all possible parameters
    param_names = ['name',
        'match_type',
        'match_all',
        'expire_exist',
        'expire',
        'cookie_name',
        'domain',
        'path',
        'insert_always',
        'dont_honor_conn']


    # put the parameters into a dictionary
    params = {}
    for curr_param_name in param_names:
        params[curr_param_name] =  module.params[curr_param_name]


    # bare base json body for the creation of the cookie persistence template
    json_post = {
        "cookie_persistence_template": {
            "name": "cookie_persistence_template",
            "expire_exist": 0,
            "expire": 0,
            "cookie_name": "",
            "domain": "",
            "path": "",
            "match_type": 0,
            "insert_always": 0,
            "dont_honor_conn": 0
        }
    }

    # modify the json body with only the parameters that have been passed in
    for pn in param_names:
        if params[pn]:
            if params[pn] == True:
                json_post['cookie_persistence_template'][pn] = 1
            else:
                json_post['cookie_persistence_template'][pn] = params[pn]
        elif params[pn] == False:
            json_post['cookie_persistence_template'][pn] = 0

    if params['name'] is None:
        module.fail_json(msg='name is required')


    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])


    # check to see if this cookie persistence template exists
    cookie_persistence_template_data = axapi_call(module, session_url + '&method=slb.template.cookie_persistence.search', json.dumps({'name': params['name']}))
    cookie_persistence_template_exists = not axapi_failure(cookie_persistence_template_data)

    changed = False
    if state == 'present':

        # if it doesn't exist then create it, otherwise update it
        if not cookie_persistence_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.cookie_persistence.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the cookie persistence template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.cookie_persistence.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the cookie persistence template: %s" % result['response']['err']['msg'])


        changed = True

    elif state == 'absent':
        if cookie_persistence_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.cookie_persistence.delete', json.dumps({'name': params['name']}))
            changed = True
        else:
            result = dict(msg="the cookie persistence template was not present")

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
