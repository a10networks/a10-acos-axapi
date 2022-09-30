#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_loopback_isis
description:
    - ISIS
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
    loopback_ifnum:
        description:
        - Key to identify parent object
        type: str
        required: True
    authentication:
        description:
        - "Field authentication"
        type: dict
        required: False
        suboptions:
            send_only_list:
                description:
                - "Field send_only_list"
                type: list
            mode_list:
                description:
                - "Field mode_list"
                type: list
            key_chain_list:
                description:
                - "Field key_chain_list"
                type: list
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
    circuit_type:
        description:
        - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2
          adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed;"
        type: str
        required: False
    csnp_interval_list:
        description:
        - "Field csnp_interval_list"
        type: list
        required: False
        suboptions:
            csnp_interval:
                description:
                - "Set CSNP interval in seconds (CSNP interval value)"
                type: int
            level:
                description:
                - "'level-1'= Speficy interval for level-1 CSNPs; 'level-2'= Specify interval for
          level-2 CSNPs;"
                type: str
    padding:
        description:
        - "Add padding to IS-IS hello packets"
        type: bool
        required: False
    hello_interval_list:
        description:
        - "Field hello_interval_list"
        type: list
        required: False
        suboptions:
            hello_interval:
                description:
                - "Set Hello interval in seconds (Hello interval value)"
                type: int
            level:
                description:
                - "'level-1'= Specify hello-interval for level-1 IIHs; 'level-2'= Specify hello-
          interval for level-2 IIHs;"
                type: str
    hello_interval_minimal_list:
        description:
        - "Field hello_interval_minimal_list"
        type: list
        required: False
        suboptions:
            hello_interval_minimal:
                description:
                - "Set Hello holdtime 1 second, interval depends on multiplier"
                type: bool
            level:
                description:
                - "'level-1'= Specify hello-interval for level-1 IIHs; 'level-2'= Specify hello-
          interval for level-2 IIHs;"
                type: str
    hello_multiplier_list:
        description:
        - "Field hello_multiplier_list"
        type: list
        required: False
        suboptions:
            hello_multiplier:
                description:
                - "Set multiplier for Hello holding time (Hello multiplier value)"
                type: int
            level:
                description:
                - "'level-1'= Specify hello multiplier for level-1 IIHs; 'level-2'= Specify hello
          multiplier for level-2 IIHs;"
                type: str
    lsp_interval:
        description:
        - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
        type: int
        required: False
    mesh_group:
        description:
        - "Field mesh_group"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "Mesh group number"
                type: int
            blocked:
                description:
                - "Block LSPs on this interface"
                type: bool
    metric_list:
        description:
        - "Field metric_list"
        type: list
        required: False
        suboptions:
            metric:
                description:
                - "Configure the metric for interface (Default metric)"
                type: int
            level:
                description:
                - "'level-1'= Apply metric to level-1 links; 'level-2'= Apply metric to level-2
          links;"
                type: str
    password_list:
        description:
        - "Field password_list"
        type: list
        required: False
        suboptions:
            password:
                description:
                - "Configure the authentication password for interface"
                type: str
            level:
                description:
                - "'level-1'= Specify password for level-1 PDUs; 'level-2'= Specify password for
          level-2 PDUs;"
                type: str
    priority_list:
        description:
        - "Field priority_list"
        type: list
        required: False
        suboptions:
            priority:
                description:
                - "Set priority for Designated Router election (Priority value)"
                type: int
            level:
                description:
                - "'level-1'= Specify priority for level-1 routing; 'level-2'= Specify priority
          for level-2 routing;"
                type: str
    retransmit_interval:
        description:
        - "Set per-LSP retransmission interval (Interval between retransmissions of the
          same LSP (seconds))"
        type: int
        required: False
    wide_metric_list:
        description:
        - "Field wide_metric_list"
        type: list
        required: False
        suboptions:
            wide_metric:
                description:
                - "Configure the wide metric for interface"
                type: int
            level:
                description:
                - "'level-1'= Apply metric to level-1 links; 'level-2'= Apply metric to level-2
          links;"
                type: str
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
    "authentication",
    "bfd_cfg",
    "circuit_type",
    "csnp_interval_list",
    "hello_interval_list",
    "hello_interval_minimal_list",
    "hello_multiplier_list",
    "lsp_interval",
    "mesh_group",
    "metric_list",
    "padding",
    "password_list",
    "priority_list",
    "retransmit_interval",
    "uuid",
    "wide_metric_list",
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
        'authentication': {
            'type': 'dict',
            'send_only_list': {
                'type': 'list',
                'send_only': {
                    'type': 'bool',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'mode_list': {
                'type': 'list',
                'mode': {
                    'type': 'str',
                    'choices': ['md5']
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'key_chain_list': {
                'type': 'list',
                'key_chain': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            }
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
        'circuit_type': {
            'type': 'str',
            'choices': ['level-1', 'level-1-2', 'level-2-only']
        },
        'csnp_interval_list': {
            'type': 'list',
            'csnp_interval': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'padding': {
            'type': 'bool',
        },
        'hello_interval_list': {
            'type': 'list',
            'hello_interval': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'hello_interval_minimal_list': {
            'type': 'list',
            'hello_interval_minimal': {
                'type': 'bool',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'hello_multiplier_list': {
            'type': 'list',
            'hello_multiplier': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'lsp_interval': {
            'type': 'int',
        },
        'mesh_group': {
            'type': 'dict',
            'value': {
                'type': 'int',
            },
            'blocked': {
                'type': 'bool',
            }
        },
        'metric_list': {
            'type': 'list',
            'metric': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'password_list': {
            'type': 'list',
            'password': {
                'type': 'str',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'priority_list': {
            'type': 'list',
            'priority': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'retransmit_interval': {
            'type': 'int',
        },
        'wide_metric_list': {
            'type': 'list',
            'wide_metric': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(loopback_ifnum=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/loopback/{loopback_ifnum}/isis"

    f_dict = {}
    if '/' in module.params["loopback_ifnum"]:
        f_dict["loopback_ifnum"] = module.params["loopback_ifnum"].replace(
            "/", "%2F")
    else:
        f_dict["loopback_ifnum"] = module.params["loopback_ifnum"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/loopback/{loopback_ifnum}/isis"

    f_dict = {}
    f_dict["loopback_ifnum"] = module.params["loopback_ifnum"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["isis"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["isis"].get(k) != v:
            change_results["changed"] = True
            config_changes["isis"][k] = v

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
    payload = utils.build_json("isis", module.params, AVAILABLE_PROPERTIES)
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
                result[
                    "acos_info"] = info["isis"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "isis-list"] if info != "NotFound" else info
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
