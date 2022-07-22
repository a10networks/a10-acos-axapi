#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_threat_intel_threat_list
description:
    - Threat Categories for malicious IPs
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "Threat category List name"
        type: str
        required: True
    ntype:
        description:
        - "'webroot'= Configure Webroot threat categories;"
        type: str
        required: False
    all_categories:
        description:
        - "Enable all categories"
        type: bool
        required: False
    spam_sources:
        description:
        - "IP's tunneling spam messages through a proxy, anomalous SMTP activities, and
          forum spam activities"
        type: bool
        required: False
    windows_exploits:
        description:
        - "IP's associated with malware, shell code, rootkits, worms or viruses"
        type: bool
        required: False
    web_attacks:
        description:
        - "IP's associated with cross site scripting, iFrame injection, SQL injection,
          cross domain injection, or domain password brute fo"
        type: bool
        required: False
    botnets:
        description:
        - "Botnet C&C channels, and infected zombie machines controlled by Bot master"
        type: bool
        required: False
    scanners:
        description:
        - "IP's associated with probes, host scan, domain scan, and password brute force
          attack"
        type: bool
        required: False
    dos_attacks:
        description:
        - "IP's participating in DOS, DDOS, anomalous sync flood, and anomalous traffic
          detection"
        type: bool
        required: False
    reputation:
        description:
        - "IP addresses currently known to be infected with malware"
        type: bool
        required: False
    phishing:
        description:
        - "IP addresses hosting phishing sites, ad click fraud or gaming fraud"
        type: bool
        required: False
    proxy:
        description:
        - "IP addresses providing proxy services"
        type: bool
        required: False
    mobile_threats:
        description:
        - "IP's associated with mobile threats"
        type: bool
        required: False
    tor_proxy:
        description:
        - "IP's providing tor proxy services"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'spam-sources'= Hits for spam sources; 'windows-exploits'= Hits for
          windows exploits; 'web-attacks'= Hits for web attacks; 'botnets'= Hits for
          botnets; 'scanners'= Hits for scanners; 'dos-attacks'= Hits for dos attacks;
          'reputation'= Hits for reputation; 'phishing'= Hits for phishing; 'proxy'= Hits
          for proxy; 'mobile-threats'= Hits for mobile threats; 'tor-proxy'= Hits for
          tor-proxy; 'total-hits'= Total hits for threat-list;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            spam_sources:
                description:
                - "Hits for spam sources"
                type: str
            windows_exploits:
                description:
                - "Hits for windows exploits"
                type: str
            web_attacks:
                description:
                - "Hits for web attacks"
                type: str
            botnets:
                description:
                - "Hits for botnets"
                type: str
            scanners:
                description:
                - "Hits for scanners"
                type: str
            dos_attacks:
                description:
                - "Hits for dos attacks"
                type: str
            reputation:
                description:
                - "Hits for reputation"
                type: str
            phishing:
                description:
                - "Hits for phishing"
                type: str
            proxy:
                description:
                - "Hits for proxy"
                type: str
            mobile_threats:
                description:
                - "Hits for mobile threats"
                type: str
            tor_proxy:
                description:
                - "Hits for tor-proxy"
                type: str
            total_hits:
                description:
                - "Total hits for threat-list"
                type: str
            name:
                description:
                - "Threat category List name"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "all_categories",
    "botnets",
    "dos_attacks",
    "mobile_threats",
    "name",
    "phishing",
    "proxy",
    "reputation",
    "sampling_enable",
    "scanners",
    "spam_sources",
    "stats",
    "tor_proxy",
    "ntype",
    "user_tag",
    "uuid",
    "web_attacks",
    "windows_exploits",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
        },
        'ntype': {
            'type': 'str',
            'choices': ['webroot']
        },
        'all_categories': {
            'type': 'bool',
        },
        'spam_sources': {
            'type': 'bool',
        },
        'windows_exploits': {
            'type': 'bool',
        },
        'web_attacks': {
            'type': 'bool',
        },
        'botnets': {
            'type': 'bool',
        },
        'scanners': {
            'type': 'bool',
        },
        'dos_attacks': {
            'type': 'bool',
        },
        'reputation': {
            'type': 'bool',
        },
        'phishing': {
            'type': 'bool',
        },
        'proxy': {
            'type': 'bool',
        },
        'mobile_threats': {
            'type': 'bool',
        },
        'tor_proxy': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'spam-sources', 'windows-exploits', 'web-attacks',
                    'botnets', 'scanners', 'dos-attacks', 'reputation',
                    'phishing', 'proxy', 'mobile-threats', 'tor-proxy',
                    'total-hits'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'spam_sources': {
                'type': 'str',
            },
            'windows_exploits': {
                'type': 'str',
            },
            'web_attacks': {
                'type': 'str',
            },
            'botnets': {
                'type': 'str',
            },
            'scanners': {
                'type': 'str',
            },
            'dos_attacks': {
                'type': 'str',
            },
            'reputation': {
                'type': 'str',
            },
            'phishing': {
                'type': 'str',
            },
            'proxy': {
                'type': 'str',
            },
            'mobile_threats': {
                'type': 'str',
            },
            'tor_proxy': {
                'type': 'str',
            },
            'total_hits': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/threat-intel/threat-list/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/threat-intel/threat-list/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["threat-list"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["threat-list"].get(k) != v:
            change_results["changed"] = True
            config_changes["threat-list"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("threat-list", module.params,
                               AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "threat-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "threat-list-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["threat-list"][
                    "stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
