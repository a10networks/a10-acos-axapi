#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_network_object
description:
    - Configure DDoS a static Monitor Network Object
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
    object_name:
        description:
        - "Field object_name"
        type: str
        required: True
    operational_mode:
        description:
        - "'monitor'= Monitor mode; 'learning'= Learning mode;"
        type: str
        required: False
    ip:
        description:
        - "Field ip"
        type: list
        required: False
        suboptions:
            subnet_ip_addr:
                description:
                - "IP Subnet, supported prefix range is from 8 to 31"
                type: str
    ipv6:
        description:
        - "Field ipv6"
        type: list
        required: False
        suboptions:
            subnet_ipv6_addr:
                description:
                - "IPV6 Subnet, supported prefix range is from 40 to 63"
                type: str
    histogram_enable:
        description:
        - "Enable histogram statistics (Default= Disabled)"
        type: bool
        required: False
    relative_auto_break_down_threshold:
        description:
        - "Field relative_auto_break_down_threshold"
        type: dict
        required: False
        suboptions:
            network_percentage:
                description:
                - "percentage of parent node"
                type: int
            permil:
                description:
                - "permil of root node"
                type: int
    static_auto_break_down_threshold:
        description:
        - "Field static_auto_break_down_threshold"
        type: dict
        required: False
        suboptions:
            network_pkt_rate:
                description:
                - "packet rate of current node"
                type: int
    service_break_down_threshold_local:
        description:
        - "Field service_break_down_threshold_local"
        type: dict
        required: False
        suboptions:
            svc_percentage:
                description:
                - "percentage of parent ip node"
                type: int
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
                - "'all'= all; 'subnet_learned'= Subnet Entry Learned; 'subnet_aged'= Subnet Entry
          Aged; 'ip_learned'= IP Entry Learned; 'ip_aged'= IP Entry Aged;
          'service_learned'= Service Entry Learned; 'service_aged'= Service Entry Aged;"
                type: str
    notification:
        description:
        - "Field notification"
        type: dict
        required: False
        suboptions:
            configuration:
                description:
                - "'configuration'= configuration;"
                type: str
            notification:
                description:
                - "Field notification"
                type: list
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
            entry_list:
                description:
                - "Field entry_list"
                type: list
            entry_count:
                description:
                - "Field entry_count"
                type: int
            details:
                description:
                - "Field details"
                type: bool
            victim_list:
                description:
                - "Field victim_list"
                type: bool
            discovered_list:
                description:
                - "Field discovered_list"
                type: bool
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            ipv4:
                description:
                - "Field ipv4"
                type: str
            ipv6:
                description:
                - "Field ipv6"
                type: str
            discovered_ip_list:
                description:
                - "Field discovered_ip_list"
                type: bool
            anomaly_ip_list:
                description:
                - "Field anomaly_ip_list"
                type: bool
            port_start:
                description:
                - "Field port_start"
                type: int
            port_end:
                description:
                - "Field port_end"
                type: int
            protocol:
                description:
                - "Field protocol"
                type: int
            single_layer_discovered_list:
                description:
                - "Field single_layer_discovered_list"
                type: bool
            object_name:
                description:
                - "Field object_name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            subnet_learned:
                description:
                - "Subnet Entry Learned"
                type: str
            subnet_aged:
                description:
                - "Subnet Entry Aged"
                type: str
            ip_learned:
                description:
                - "IP Entry Learned"
                type: str
            ip_aged:
                description:
                - "IP Entry Aged"
                type: str
            service_learned:
                description:
                - "Service Entry Learned"
                type: str
            service_aged:
                description:
                - "Service Entry Aged"
                type: str
            object_name:
                description:
                - "Field object_name"
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
AVAILABLE_PROPERTIES = ["histogram_enable", "ip", "ipv6", "notification", "object_name", "oper", "operational_mode", "relative_auto_break_down_threshold", "sampling_enable", "service_break_down_threshold_local", "static_auto_break_down_threshold", "stats", "user_tag", "uuid", ]


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
        'object_name': {
            'type': 'str',
            'required': True,
            },
        'operational_mode': {
            'type': 'str',
            'choices': ['monitor', 'learning']
            },
        'ip': {
            'type': 'list',
            'subnet_ip_addr': {
                'type': 'str',
                }
            },
        'ipv6': {
            'type': 'list',
            'subnet_ipv6_addr': {
                'type': 'str',
                }
            },
        'histogram_enable': {
            'type': 'bool',
            },
        'relative_auto_break_down_threshold': {
            'type': 'dict',
            'network_percentage': {
                'type': 'int',
                },
            'permil': {
                'type': 'int',
                }
            },
        'static_auto_break_down_threshold': {
            'type': 'dict',
            'network_pkt_rate': {
                'type': 'int',
                }
            },
        'service_break_down_threshold_local': {
            'type': 'dict',
            'svc_percentage': {
                'type': 'int',
                }
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
                'type': 'str',
                'choices': ['all', 'subnet_learned', 'subnet_aged', 'ip_learned', 'ip_aged', 'service_learned', 'service_aged']
                }
            },
        'notification': {
            'type': 'dict',
            'configuration': {
                'type': 'str',
                'choices': ['configuration']
                },
            'notification': {
                'type': 'list',
                'notification_template_name': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'entry_list': {
                'type': 'list',
                'address': {
                    'type': 'str',
                    },
                'children_count': {
                    'type': 'int',
                    },
                'port_range_start': {
                    'type': 'int',
                    },
                'port_range_end': {
                    'type': 'int',
                    },
                'port': {
                    'type': 'int',
                    },
                'service_protocol': {
                    'type': 'str',
                    },
                'indicators': {
                    'type': 'list',
                    'indicator_name': {
                        'type': 'str',
                        },
                    'indicator_index': {
                        'type': 'int',
                        },
                    'value': {
                        'type': 'list',
                        'current': {
                            'type': 'str',
                            },
                        'threshold': {
                            'type': 'str',
                            }
                        },
                    'is_anomaly': {
                        'type': 'int',
                        }
                    },
                'is_anomaly': {
                    'type': 'int',
                    },
                'is_learning_done': {
                    'type': 'int',
                    },
                'is_histogram_learning_done': {
                    'type': 'int',
                    },
                'operational_mode': {
                    'type': 'int',
                    },
                'es_timestamp': {
                    'type': 'str',
                    },
                'de_es_timestamp': {
                    'type': 'str',
                    }
                },
            'entry_count': {
                'type': 'int',
                },
            'details': {
                'type': 'bool',
                },
            'victim_list': {
                'type': 'bool',
                },
            'discovered_list': {
                'type': 'bool',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'ipv4': {
                'type': 'str',
                },
            'ipv6': {
                'type': 'str',
                },
            'discovered_ip_list': {
                'type': 'bool',
                },
            'anomaly_ip_list': {
                'type': 'bool',
                },
            'port_start': {
                'type': 'int',
                },
            'port_end': {
                'type': 'int',
                },
            'protocol': {
                'type': 'int',
                },
            'single_layer_discovered_list': {
                'type': 'bool',
                },
            'object_name': {
                'type': 'str',
                'required': True,
                }
            },
        'stats': {
            'type': 'dict',
            'subnet_learned': {
                'type': 'str',
                },
            'subnet_aged': {
                'type': 'str',
                },
            'ip_learned': {
                'type': 'str',
                },
            'ip_aged': {
                'type': 'str',
                },
            'service_learned': {
                'type': 'str',
                },
            'service_aged': {
                'type': 'str',
                },
            'object_name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/network-object/{object_name}"

    f_dict = {}
    if '/' in str(module.params["object_name"]):
        f_dict["object_name"] = module.params["object_name"].replace("/", "%2F")
    else:
        f_dict["object_name"] = module.params["object_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/network-object"

    f_dict = {}
    f_dict["object_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["network-object"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["network-object"].get(k) != v:
            change_results["changed"] = True
            config_changes["network-object"][k] = v

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
    payload = utils.build_json("network-object", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["network-object"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["network-object-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["network-object"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["network-object"]["stats"] if info != "NotFound" else info
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
