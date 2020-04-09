#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
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
module: a10_health_monitor
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb health monitor objects on A10 Networks devices via aXAPI
author: "Fadi Hafez (@fhafez)"
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
      - L3V partition to add these health monitors to
    required: false
    default: null
    choices: []
  hm_name:
    description:
      - health monitor name
    required: true
    aliases: ['hm']
  interval:
    description:
      - hm interval in seconds
    required: false
    default: 5
    aliases: ['int']
  timeout:
    description:
      - hm timeout in seconds
    required: false
    default: 5
  retry:
    description:
      - hm retry count
    required: false
    default: 3
  consec_pass_reqd:
    description:
      - consecutive passes required
    required: false
    choices: [0, 1]
    default: 1
  disable_after_down:
    description:
      - keep disabled when down
    required: false
    default: false
    choices: [0, 1]
  override_ipv4: 
    description:
      - override the destination IPv4
    required: false
    default: "0.0.0.0"
  override_ipv6: 
    description:
      - override the destination IPv6
    required: false
    default: "::"
  override_port:
     description:
      - override the destination L4 port
    required: false
    default: 0
  strictly_retry:
    description:
      - do a strictly retry
    required: false
    choices: [0, 1]
    default: 0
  icmp:
    description:
      - make a icmp health monitor
    required: false
    default: []
  tcp:
    description:
      - make a tcp health monitor
    required: false
    default: []
  udp:
    description:
      - make a udp health monitor
    required: false
    default: []
  http:
    description:
      - make a http health monitor
    required: false
    default: []
  https:
    description:
      - make a https health monitor
    required: false
    default: []
  ftp:
    description:
      - make an ftp health monitor
    required: false
    default: []
  smtp:
    description:
      - make an smtp health monitor
    required: false
    default: []
  pop3:
    description:
      - make an pop3 health monitor
    required: false
    default: []
  snmp:
    description:
      - make an snmp health monitor
    required: false
    default: []
  dns:
    description:
      - make an dns health monitor
    required: false
    default: []
  radius:
    description:
      - make an radius health monitor
    required: false
    default: []
  ldap:
    description:
      - make an ldap health monitor
    required: false
    default: []
  rtsp:
    description:
      - make an rtsp health monitor
    required: false
    default: []
  sip:
    description:
      - make an sip health monitor
    required: false
    default: []
  ntp:
    description:
      - make an ntp health monitor
    required: false
    default: []
  imap:
    description:
      - make an imap health monitor
    required: false
    default: []
  database:
    description:
      - make an database health monitor
    required: false
    default: []
  compound:
    description:
      - make an compound health monitor
    required: false
    default: []
  database:
    description:
      - make an database health monitor
    required: false
    default: []
  external:
    description:
      - make an external health monitor
    required: false
    default: []
  state:
    description:
      - absent or present for delete or creating of HM
    required: false
    default: absent 
    choices: ["present", "absent"]
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
# Create a new health monitor
- a10_health_monitor_v2: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: RCSIN_PRV
    hm_name: ws_hm
    interval: 4
    timeout: 4
    retry: 2
    disable_after_down: true
    consec_pass_reqd: 1
    external:
      - program: checkServerStatus
        server_port: 2245
        arguments: ""
        preference: 1
'''

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            hm_name=dict(type='str', aliases=['hm'], required=True),
            interval=dict(type='int', default=5, aliases=['int']),
            timeout=dict(type='int', default=5),
            retry=dict(type='int', default=3),
            strictly_retry=dict(type='int', default=0, choices=[0, 1]),
            override_ipv4=dict(type='str', default='0.0.0.0'),
            override_ipv6=dict(type='str', default='::'),
            override_port=dict(type='int', default=0),
            disable_after_down=dict(type='int', default=0, choices=[0, 1]),
            consec_pass_reqd=dict(type='int', default=1),
            icmp=dict(type='dict', default=None),
            tcp=dict(type='dict', default=None),
            udp=dict(type='dict', default={}),
            http=dict(type='dict', default={}),
            https=dict(type='dict', default={}),
            ftp=dict(type='dict', default={}),
            smtp=dict(type='dict', default={}),
            pop3=dict(type='dict', default={}),
            snmp=dict(type='dict', default={}),
            dns=dict(type='dict', default={}),
            radius=dict(type='dict', default={}),
            ldap=dict(type='dict', default={}),
            rtsp=dict(type='dict', default={}),
            sip=dict(type='dict', default={}),
            ntp=dict(type='dict', default={}),
            imap=dict(type='dict', default={}),
            database=dict(type='dict', default={}),
            compound=dict(type='dict', default={}),
            external=dict(type='dict', default={})
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    # retrieve all the parameters
    state = module.params['state']
    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    write_config = module.params['write_config']

    # create a list of all possible parameters
    param_names = ['hm_name',
        'interval',
        'timeout',
        'retry',
        'disable_after_down',
        'consec_pass_reqd',
        'strictly_retry',
        'override_ipv4',
        'override_ipv6',
        'override_port',
        'icmp',
        'tcp',
        'udp',
        'http',
        'https',
        'ftp',
        'smtp',
        'pop3',
        'snmp',
        'dns',
        'radius',
        'ldap',
        'rtsp',
        'sip',
        'ntp',
        'imap',
        'database',
        'compound',
        'external']


    # put the parameters into a dictionary
    params = {}
    for curr_param_name in param_names:
        params[curr_param_name] =  module.params[curr_param_name]

    # hm_name name is mandatory
    if params['hm_name'] is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'http://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg=result['response']['err']['msg'])

    # absent means to delete the health monitor (only the hm_name is required)
    if state == 'absent':
        json_post = {
            'health_monitor': {
                'name': params['hm_name'],
            }
        }

    else:

        # bare base json body for the creation of any health monitor
        json_post = {
            "health_monitor": {
                "name": params['hm_name'],
                "interval": params['interval'],
                "timeout": params['timeout'],
                "retry": params['retry'],
                "disable_after_down": params['disable_after_down'],
                "consec_pass_reqd": params['consec_pass_reqd'],
                "strictly_retry": params['strictly_retry'],
                "override_ipv4": params['override_ipv4'],
                "override_ipv6": params['override_ipv6'],
                "override_port": params['override_port'],
            }
        }

        # add the right type to the json_post (there are 0 to 18 types)

        # if icmp was listed in the task, even if its an empty dict
        if params['icmp'] or params['icmp'] == {}:
            json_post['health_monitor']['type'] = 0
            json_post['health_monitor']['icmp'] = {
                "mode": 0,
                "passive": {
                    "status": 0,
                    "status_code_2xx": 0,
                    "threshold": 75,
                    "sample_threshold": 50,
                    "interval": 10
                }
            }

            # override icmp default parameters with the ones provided
            for icmp_item in params['icmp']:
                json_post['health_monitor']['icmp'][icmp_item] = params['icmp'][icmp_item]

        elif params['tcp'] or params['tcp'] == {}:
            json_post['health_monitor']['type'] = 1
            json_post['health_monitor']['tcp'] = {
                "port": 0,
                "half_open": 0,
                "send": "",
                "receive": ""
            }

            # override tcp default parameters with the ones provided
            for tcp_item in params['tcp']:
                json_post['health_monitor']['tcp'][tcp_item] = params['tcp'][tcp_item]

        elif params['udp']:
            json_post['health_monitor']['type'] = 2
            json_post['health_monitor']['udp'] = params['udp']
       
        elif params['http']:
            json_post['health_monitor']['type'] = 3
            json_post['health_monitor']['http'] = {
                "port": 0,
                "host": "",
                "url": "",
                "user": "",
                "password": "",
                "expect_code": "200",
                "maintenance_code": "",
                "passive": {
                    "status": 0,
                    "status_code_2xx": 0,
                    "threshold": 75,
                    "sample_threshold": 50,
                    "interval": 10
                }
            }
            for http_item in params['http']:
                json_post['health_monitor']['http'][http_item] = params['http'][http_item]
       
        elif params['https']:
            json_post['health_monitor']['type'] = 4
            json_post['health_monitor']['https'] = {
                "port": 443,
                "host": "",
                "url": "GET /",
                "user": "",
                "password": "",
                "expect_code": "",
                "maintenance_code": "",
                "sslv2hello_status": 0,
                "cert_name": "",
                "key_name": "",
                "pass_phrase": "",
                "passive": {
                    "status": 0,
                    "status_code_2xx": 0,
                    "threshold": 75,
                    "sample_threshold": 50,
                    "interval": 10
                }
            }

            for https_item in params['https']:
                json_post['health_monitor']['https'][https_item] = params['https'][https_item]
       
        elif params['ftp']:
            json_post['health_monitor']['type'] = 5
            json_post['health_monitor']['ftp'] = params['ftp']
       
        elif params['smtp']:
            json_post['health_monitor']['type'] = 6
            json_post['health_monitor']['smtp'] = params['smtp']
       
        elif params['pop3']:
            json_post['health_monitor']['type'] = 7
            json_post['health_monitor']['pop3'] = params['pop3']
       
        elif params['snmp']:
            json_post['health_monitor']['type'] = 8
            json_post['health_monitor']['snmp'] = params['snmp']
       
        elif params['dns']:
            json_post['health_monitor']['type'] = 9
            json_post['health_monitor']['dns'] = params['dns']
       
        elif params['radius']:
            json_post['health_monitor']['type'] = 10
            json_post['health_monitor']['radius'] = params['radius']
       
        elif params['ldap']:
            json_post['health_monitor']['type'] = 11
            json_post['health_monitor']['ldap'] = params['ldap']
       
        elif params['rtsp']:
            json_post['health_monitor']['type'] = 12
            json_post['health_monitor']['rtsp'] = params['rtsp']
       
        elif params['sip']:
            json_post['health_monitor']['type'] = 13
            json_post['health_monitor']['sip'] = params['sip']
       
        elif params['ntp']:
            json_post['health_monitor']['type'] = 14
            json_post['health_monitor']['ntp'] = params['ntp']
       
        elif params['imap']:
            json_post['health_monitor']['type'] = 15
            json_post['health_monitor']['imap'] = params['imap']
       
        elif params['database']:
            json_post['health_monitor']['type'] = 16
            json_post['health_monitor']['database'] = params['database']
       
        elif params['compound']:
            json_post['health_monitor']['type'] = 17
            json_post['health_monitor']['compound'] = params['compound']
       
        elif params['external']:

            # if a program has been passed in then make sure the program being run in this health monitor actually exists already
            if not 'program' in params['external']:
                # log out of the session nicely and exit with error
                axapi_call(module, session_url + '&method=session.close')
                module.fail_json(msg="you must include a program when creating an external health monitor")
            else:
                result = axapi_call(module, session_url + '&method=slb.hm.external.search', json.dumps({'name': params['external']['program']}))

                if axapi_failure(result):
                    # log out of the session nicely and exit with error
                    axapi_call(module, session_url + '&method=session.close')
                    module.fail_json(msg="failed to create the health monitor: %s" % result['response']['err']['msg'])

                json_post['health_monitor']['type'] = 18
                json_post['health_monitor']['external'] = params['external']
       
        else:
            # log out of the session nicely and exit with error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg="you must include one of icmp, tcp, udp, http, https, ftp, smtp, pop3 etc.")


    changed = False

    # present means the health monitor is being added
    if state == 'present':
        if not params['hm_name']:
            # log out of the session nicely and exit with error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg='you must specify a name when creating a health monitor')

        # check if the health monitor already exists
        hm_data = axapi_call(module, session_url + '&method=slb.hm.search', json.dumps({'name': params['hm_name']}))
        hm_exists = not axapi_failure(hm_data)
        hm_data_str = json.dumps(hm_data)

        # this is the makeshift way to detecting that a health monitor exists
        # because when a health monitor contains carriage returns then the traditional axapi_failure will always return True
        if "response" in hm_data_str and "fail" in hm_data_str and "code" in hm_data_str:
            hm_exists = False
        else:
            hm_exists = True

        if not hm_exists:
## DEBUGGING! ##
#            module.fail_json(msg=hm_data)
###########
            result = axapi_call(module, session_url + '&method=slb.hm.create', json.dumps(json_post))
            if axapi_failure(result):
                # log out of the session nicely and exit with error
                axapi_call(module, session_url + '&method=session.close')
                module.fail_json(msg="failed to create the health monitor: %s" % result['response']['err']['msg'])
        else:
            result = axapi_call(module, session_url + '&method=slb.hm.update', json.dumps(json_post))
            if axapi_failure(result):
                # log out of the session nicely and exit with error
                axapi_call(module, session_url + '&method=session.close')
                module.fail_json(msg="failed to update the health monitor: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        result = axapi_call(module, session_url + '&method=slb.hm.delete', json.dumps(json_post['health_monitor']))
        if axapi_failure(result):
            # log out of the session nicely and exit with error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg="failed to delete the health monitor: %s" % result['response']['err']['msg'])

        changed = True


    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            # log out of the session nicely and exit with error
            axapi_call(module, session_url + '&method=session.close')
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
