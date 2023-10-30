#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ng_waf
description:
    - NGWAF related commands
author: A10 Networks
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stats_list:
        description:
        - "Field stats_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "ng-waf name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    status:
        description:
        - "Field status"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    custom_page:
        description:
        - "Field custom_page"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    custom_signals:
        description:
        - "Field custom_signals"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cpu:
        description:
        - "Field cpu"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ngwaf_stats_list:
                description:
                - "Field ngwaf_stats_list"
                type: list
            vserver:
                description:
                - "Field vserver"
                type: str
            vport:
                description:
                - "Field vport"
                type: str
            cache_vserver:
                description:
                - "Field cache_vserver"
                type: str
            cache_vport:
                description:
                - "Field cache_vport"
                type: str
            clear_all:
                description:
                - "Field clear_all"
                type: bool
            status:
                description:
                - "Field status"
                type: dict
            custom_page:
                description:
                - "Field custom_page"
                type: dict
            custom_signals:
                description:
                - "Field custom_signals"
                type: dict
            cpu:
                description:
                - "Field cpu"
                type: dict
    stats:
        description:
        - "Field stats"
        type: str
        required: False
        suboptions:
            name:
                description:
                - "ng-waf name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
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
AVAILABLE_PROPERTIES = ["cpu", "custom_page", "custom_signals", "oper", "stats", "stats_list", "status", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
            },
        'stats_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'status': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'custom_page': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'custom_signals': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'cpu': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'ngwaf_stats_list': {
                'type': 'list',
                'ntype': {
                    'type': 'str',
                    },
                'name': {
                    'type': 'str',
                    },
                'count': {
                    'type': 'int',
                    }
                },
            'vserver': {
                'type': 'str',
                },
            'vport': {
                'type': 'str',
                },
            'cache_vserver': {
                'type': 'str',
                },
            'cache_vport': {
                'type': 'str',
                },
            'clear_all': {
                'type': 'bool',
                },
            'status': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ngwaf_version': {
                        'type': 'str',
                        },
                    'partition_list': {
                        'type': 'list',
                        'partition_name': {
                            'type': 'str',
                            },
                        'status': {
                            'type': 'str',
                            },
                        'agent_name': {
                            'type': 'str',
                            },
                        'access_key_id': {
                            'type': 'str',
                            },
                        'secret_access_key': {
                            'type': 'str',
                            },
                        'cache_entries': {
                            'type': 'int',
                            },
                        'tracked_custom_signal': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'custom_page': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'file_list': {
                        'type': 'list',
                        'file': {
                            'type': 'str',
                            },
                        'size': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'custom_signals': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'signal_list': {
                        'type': 'list',
                        'signal': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'cpu': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'number_of_cpus': {
                        'type': 'int',
                        },
                    'cpu_info': {
                        'type': 'list',
                        'cpu_id': {
                            'type': 'int',
                            },
                        '1_sec': {
                            'type': 'int',
                            },
                        '5_sec': {
                            'type': 'int',
                            },
                        '10_sec': {
                            'type': 'int',
                            },
                        '30_sec': {
                            'type': 'int',
                            },
                        '60_sec': {
                            'type': 'int',
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'str',
            'required': False,
            'name': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ng-waf"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ng-waf"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ng-waf"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ng-waf"].get(k) != v:
            change_results["changed"] = True
            config_changes["ng-waf"][k] = v

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
    payload = utils.build_json("ng-waf", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

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
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["ng-waf"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ng-waf-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["ng-waf"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ng-waf"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
