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
module: a10_client_ssl_template
version_added: 2.2.0.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage client ssl template objects on A10 Networks devices via aXAPI
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
      - L3V partition to add/remove template to/from.  Will be added to 'shared' if not specified
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
  cert_name:
    description:
      - certificate name
      - length is 0 to 255 characters
    required: false
    default: ""
  chain_cert_name:
    description:
      - certificate key-chain
      - length is 0 to 271 characters
    required: false
    default: ""
  key_name:
    description:
      - certificate key
      - length is 0 to 255 characters
    required: false
    default: ""
  pass_phrase:
    description:
      - pass phrase used to encrypt the key
      - length is 0 to 79 characters
    required: false
    default: ""
  cache_size:
    description:
      - session cache size
      - range is 0 to 8000000
    required: false
    default: 0
  ssl_false_start:
    description:
      - SSL False Start support for Google Chrome Browser
    required: false
    choices: ["yes","no"]
    default: False
  ssl_forward_proxy:
    description:
      - is this used for ssl insight?
    required: false
    choices: ["yes", "no"]
    default: False
  ca_cert_name:
    description:
      - Certificate Authority to use for validating client certs
      - length is 0 to 255
    required: false
    default: ""
  ca_key_name:
    description:
      - ssl key name for CA
      - length is 0 to 255
    required: false
    default: ""
  ca_pass_phrase:
    description:
      - pass phrase used for encrypting ca cert
      - length is 0 to 79 characters
    required: false
    default: ""
  server_name_indication_list:
    description:
      - a list of SNI sub elements
      - a SNI element contains
      -   name (up to 63 characters)
      -   cert_name (up to 271 characters)
      -   key_name (up to 271 characters)
    required: false
    default: []
  client_check_mode:
    description:
      - check client
      - 0=require, 1=request, 2=ignore
    required: false
    choices: [0,1,2]
    default: 0
  client_close_notify:
    description:
      - enable close alerts for SSL sessions
    required: false
    default: False
  client_cert_rev_list:
    description:
      - client certificate reverse list
      - length is 0 to 255
    required: false
    default: ""
  ca_cert_list:
    description:
      - a list of CA certs
      - ca_cert element contains
      -   name
    required: false
    default: []
  cipher_list:
    description:
      - cipher list to support for certs from clients
      - a list of integers from the following
      -   0. SSL3_RSA_RC4_40_MD5
      -   1. SSL3_RSA_RC4_128_MD5
      -   2. SSL3_RSA_RC4_128_SHA
      -   3. SSL3_RSA_DES_40_CBC_SHA
      -   4. SSL3_RSA_DES_64_CBC_SHA
      -   5. SSL3_RSA_DES_192_CBC3_SHA
      -   6. TLS1_RSA_EXPORT1024_RC4_56_MD5
      -   7. TLS1_RSA_EXPORT1024_RC4_56_SHA
      -   8. TLS1_RSA_AES_128_SHA
      -   9. TLS1_RSA_AES_256_SHA
      -   10. TLS1_RSA_AES_128_SHA256
      -   11. TLS1_RSA_AES_256_SHA256.
    default: []
  cipher_tmpl_name:
    description:
      - cipher template to use
      - length is 0 to 79 characters
    required: false
    default: ""
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
# Create a new Client SSL Template
- a10_client_ssl_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_client_ssl_templ
    cert_name: cert_app
    key_name: cert_app
    cipher_list: [6, 7, 8, 9, 10]

'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            cert_name=dict(type='str', default=None),
            chain_cert_name=dict(type='str', default=None),
            key_name=dict(type='str', default=None),
            pass_phrase=dict(type='str', default=None),
            cache_size=dict(type='int', default=0),
            ssl_false_start=dict(type='bool', default=False),
            ssl_forward_proxy=dict(type='bool', default=False),
            ca_cert_name=dict(type='str', default=None),
            ca_key_name=dict(type='str', default=None),
            ca_pass_phrase=dict(type='str', default=None),
            server_name_indication_list=dict(type='list', default=[]),
            client_check_mode=dict(type='int', default=0),
            client_close_notify=dict(type='bool', default=False),
            client_cert_rev_list=dict(type='str', default=None),
            ca_cert_list=dict(type='list', default=[]),
            cipher_list=dict(type='list', default=[]),
            cipher_tmpl_name=dict(type='str', default=None)
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

    cert_name = module.params['cert_name']
    chain_cert_name = module.params['chain_cert_name']
    key_name = module.params['key_name']
    pass_phrase = module.params['pass_phrase']
    cache_size = module.params['cache_size']
    ssl_false_start = module.params['ssl_false_start']
    ssl_forward_proxy = module.params['ssl_forward_proxy']
    ca_cert_name = module.params['ca_cert_name']
    ca_key_name = module.params['ca_key_name']
    ca_pass_phrase = module.params['ca_pass_phrase']
    server_name_indication_list = module.params['server_name_indication_list']
    client_check_mode = module.params['client_check_mode']
    client_close_notify = module.params['client_close_notify']
    client_cert_rev_list = module.params['client_cert_rev_list']
    ca_cert_list = module.params['ca_cert_list']
    cipher_list = module.params['cipher_list']
    cipher_tmpl_name = module.params['cipher_tmpl_name']

    if name is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

        # certificates/keys must be preceded with the partition name they're in
        if key_name:
            key_name = '?' + part + '?' + key_name

        if ca_key_name:
            ca_key_name = '?' + part + '?' + ca_key_name

        if cert_name:
            cert_name = '?' + part + '?' + cert_name

        if chain_cert_name:
            chain_cert_name = '?' + part + '?' + chain_cert_name

        if ca_cert_list and len(ca_cert_list) > 0:
            for curr_cert in ca_cert_list:
                curr_cert['name'] = '?' + part + '?' + curr_cert['name']


    # populate the json body for the creation of the http template
    json_post = {
        'client_ssl_template': {
            'name': name,
        }
    }

    if cert_name:
        json_post['cert_name'] = cert_name

    if chain_cert_name:
        json_post['chain_cert_name'] = chain_cert_name

    if key_name:
        json_post['key_name'] = key_name

    if pass_phrase:
        json_post['pass_phrase'] = pass_phrase

    if cache_size:
        json_post['cache_size'] = cache_size

    if ssl_false_start:
        json_post['ssl_false_start'] = ssl_false_start
   
    if ssl_forward_proxy:
        json_post['ssl_forward_proxy'] = ssl_forward_proxy

    if ca_cert_name:
        json_post['ca_cert_name'] = ca_cert_name

    if ca_key_name:
        json_post['ca_key_name'] = ca_key_name

    if ca_pass_phrase:
        json_post['ca_pass_phrase'] = ca_pass_phrase

    if server_name_indication_list:
        json_post['server_name_indication_list'] = server_name_indication_list

    if client_check_mode:
        json_post['client_check_mode'] = client_check_mode

    if client_close_notify:
        json_post['client_close_notify'] = client_close_notify

    if client_cert_rev_list:
        json_post['client_cert_rev_list'] = client_cert_rev_list

    if ca_cert_list:
        json_post['ca_cert_list'] = ca_cert_list

    if cipher_list and len(cipher_list) > 0:
        json_post['cipher_list'] = []
        for cipher in cipher_list:
            json_post['cipher_list'].append({'cipher': cipher})

    if cipher_tmpl_name:
        json_post['cipher_tmpl_name'] = cipher_tmpl_name


    # check to see if this client ssl template exists
    client_ssl_template_data = axapi_call(module, session_url + '&method=slb.template.client_ssl.search', json.dumps({'name': name}))
    client_ssl_template_exists = not axapi_failure(client_ssl_template_data)

    changed = False
    if state == 'present':
        if not client_ssl_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.client_ssl.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the client ssl template: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.template.client_ssl.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the client ssl template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if client_ssl_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.client_ssl.delete', json.dumps({'name': name}))
            changed = True
        else:
            result = dict(msg="the client ssl template was not present")

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
