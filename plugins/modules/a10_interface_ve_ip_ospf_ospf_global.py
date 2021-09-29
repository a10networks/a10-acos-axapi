#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_ve_ip_ospf_ospf_global
description:
    - Global setting for Open Shortest Path First for IPv4 (OSPF)
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
    ve_ifnum:
        description:
        - Key to identify parent object
        type: str
        required: True
    authentication_cfg:
        description:
        - "Field authentication_cfg"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Enable authentication"
                type: bool
            value:
                description:
                - "'message-digest'= Use message-digest authentication; 'null'= Use no
          authentication;"
                type: str
    authentication_key:
        description:
        - "Authentication password (key) (The OSPF password (key))"
        type: str
        required: False
    bfd_cfg:
        description:
        - "Field bfd_cfg"
        type: dict
        required: False
        suboptions:
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
                type: bool
            disable:
                description:
                - "Disable BFD"
                type: bool
    cost:
        description:
        - "Interface cost"
        type: int
        required: False
    database_filter_cfg:
        description:
        - "Field database_filter_cfg"
        type: dict
        required: False
        suboptions:
            database_filter:
                description:
                - "'all'= Filter all LSA;"
                type: str
            out:
                description:
                - "Outgoing LSA"
                type: bool
    dead_interval:
        description:
        - "Interval after which a neighbor is declared dead (Seconds)"
        type: int
        required: False
    disable:
        description:
        - "'all'= All functionality;"
        type: str
        required: False
    hello_interval:
        description:
        - "Time between HELLO packets (Seconds)"
        type: int
        required: False
    message_digest_cfg:
        description:
        - "Field message_digest_cfg"
        type: list
        required: False
        suboptions:
            message_digest_key:
                description:
                - "Message digest authentication password (key) (Key id)"
                type: int
            md5:
                description:
                - "Field md5"
                type: dict
    mtu:
        description:
        - "OSPF interface MTU (MTU size)"
        type: int
        required: False
    mtu_ignore:
        description:
        - "Ignores the MTU in DBD packets"
        type: bool
        required: False
    network:
        description:
        - "Field network"
        type: dict
        required: False
        suboptions:
            broadcast:
                description:
                - "Specify OSPF broadcast multi-access network"
                type: bool
            non_broadcast:
                description:
                - "Specify OSPF NBMA network"
                type: bool
            point_to_point:
                description:
                - "Specify OSPF point-to-point network"
                type: bool
            point_to_multipoint:
                description:
                - "Specify OSPF point-to-multipoint network"
                type: bool
            p2mp_nbma:
                description:
                - "Specify non-broadcast point-to-multipoint network"
                type: bool
    priority:
        description:
        - "Router priority"
        type: int
        required: False
    retransmit_interval:
        description:
        - "Time between retransmitting lost link state advertisements (Seconds)"
        type: int
        required: False
    transmit_delay:
        description:
        - "Link state transmit delay (Seconds)"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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
    "authentication_cfg",
    "authentication_key",
    "bfd_cfg",
    "cost",
    "database_filter_cfg",
    "dead_interval",
    "disable",
    "hello_interval",
    "message_digest_cfg",
    "mtu",
    "mtu_ignore",
    "network",
    "priority",
    "retransmit_interval",
    "transmit_delay",
    "uuid",
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
        'authentication_cfg': {
            'type': 'dict',
            'authentication': {
                'type': 'bool',
            },
            'value': {
                'type': 'str',
                'choices': ['message-digest', 'null']
            }
        },
        'authentication_key': {
            'type': 'str',
        },
        'bfd_cfg': {
            'type': 'dict',
            'bfd': {
                'type': 'bool',
            },
            'disable': {
                'type': 'bool',
            }
        },
        'cost': {
            'type': 'int',
        },
        'database_filter_cfg': {
            'type': 'dict',
            'database_filter': {
                'type': 'str',
                'choices': ['all']
            },
            'out': {
                'type': 'bool',
            }
        },
        'dead_interval': {
            'type': 'int',
        },
        'disable': {
            'type': 'str',
            'choices': ['all']
        },
        'hello_interval': {
            'type': 'int',
        },
        'message_digest_cfg': {
            'type': 'list',
            'message_digest_key': {
                'type': 'int',
            },
            'md5': {
                'type': 'dict',
                'md5_value': {
                    'type': 'str',
                },
                'encrypted': {
                    'type': 'str',
                }
            }
        },
        'mtu': {
            'type': 'int',
        },
        'mtu_ignore': {
            'type': 'bool',
        },
        'network': {
            'type': 'dict',
            'broadcast': {
                'type': 'bool',
            },
            'non_broadcast': {
                'type': 'bool',
            },
            'point_to_point': {
                'type': 'bool',
            },
            'point_to_multipoint': {
                'type': 'bool',
            },
            'p2mp_nbma': {
                'type': 'bool',
            }
        },
        'priority': {
            'type': 'int',
        },
        'retransmit_interval': {
            'type': 'int',
        },
        'transmit_delay': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(ve_ifnum=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ip/ospf/ospf-global"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ip/ospf/ospf-global"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ospf-global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ospf-global"].get(k) != v:
            change_results["changed"] = True
            config_changes["ospf-global"][k] = v

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
    payload = utils.build_json("ospf-global", module.params,
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
                    "ospf-global"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "ospf-global-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
