#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_resource_accounting_template
description:
    - Create resource accounting template
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
        - "Enter template name"
        type: str
        required: True
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
    app_resources:
        description:
        - "Field app_resources"
        type: dict
        required: False
        suboptions:
            gslb_device_cfg:
                description:
                - "Field gslb_device_cfg"
                type: dict
            gslb_geo_location_cfg:
                description:
                - "Field gslb_geo_location_cfg"
                type: dict
            gslb_ip_list_cfg:
                description:
                - "Field gslb_ip_list_cfg"
                type: dict
            gslb_policy_cfg:
                description:
                - "Field gslb_policy_cfg"
                type: dict
            gslb_service_cfg:
                description:
                - "Field gslb_service_cfg"
                type: dict
            gslb_service_ip_cfg:
                description:
                - "Field gslb_service_ip_cfg"
                type: dict
            gslb_service_port_cfg:
                description:
                - "Field gslb_service_port_cfg"
                type: dict
            gslb_site_cfg:
                description:
                - "Field gslb_site_cfg"
                type: dict
            gslb_svc_group_cfg:
                description:
                - "Field gslb_svc_group_cfg"
                type: dict
            gslb_template_cfg:
                description:
                - "Field gslb_template_cfg"
                type: dict
            gslb_zone_cfg:
                description:
                - "Field gslb_zone_cfg"
                type: dict
            health_monitor_cfg:
                description:
                - "Field health_monitor_cfg"
                type: dict
            real_port_cfg:
                description:
                - "Field real_port_cfg"
                type: dict
            real_server_cfg:
                description:
                - "Field real_server_cfg"
                type: dict
            service_group_cfg:
                description:
                - "Field service_group_cfg"
                type: dict
            virtual_server_cfg:
                description:
                - "Field virtual_server_cfg"
                type: dict
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    network_resources:
        description:
        - "Field network_resources"
        type: dict
        required: False
        suboptions:
            static_ipv4_route_cfg:
                description:
                - "Field static_ipv4_route_cfg"
                type: dict
            static_ipv6_route_cfg:
                description:
                - "Field static_ipv6_route_cfg"
                type: dict
            ipv4_acl_line_cfg:
                description:
                - "Field ipv4_acl_line_cfg"
                type: dict
            ipv6_acl_line_cfg:
                description:
                - "Field ipv6_acl_line_cfg"
                type: dict
            static_arp_cfg:
                description:
                - "Field static_arp_cfg"
                type: dict
            static_neighbor_cfg:
                description:
                - "Field static_neighbor_cfg"
                type: dict
            static_mac_cfg:
                description:
                - "Field static_mac_cfg"
                type: dict
            object_group_cfg:
                description:
                - "Field object_group_cfg"
                type: dict
            object_group_clause_cfg:
                description:
                - "Field object_group_clause_cfg"
                type: dict
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    system_resources:
        description:
        - "Field system_resources"
        type: dict
        required: False
        suboptions:
            bw_limit_cfg:
                description:
                - "Field bw_limit_cfg"
                type: dict
            concurrent_session_limit_cfg:
                description:
                - "Field concurrent_session_limit_cfg"
                type: dict
            l4_session_limit_cfg:
                description:
                - "Field l4_session_limit_cfg"
                type: dict
            l4cps_limit_cfg:
                description:
                - "Field l4cps_limit_cfg"
                type: dict
            l7cps_limit_cfg:
                description:
                - "Field l7cps_limit_cfg"
                type: dict
            natcps_limit_cfg:
                description:
                - "Field natcps_limit_cfg"
                type: dict
            fwcps_limit_cfg:
                description:
                - "Field fwcps_limit_cfg"
                type: dict
            ssl_throughput_limit_cfg:
                description:
                - "Field ssl_throughput_limit_cfg"
                type: dict
            sslcps_limit_cfg:
                description:
                - "Field sslcps_limit_cfg"
                type: dict
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
                type: int
            uuid:
                description:
                - "uuid of the object"
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
    "app_resources",
    "name",
    "network_resources",
    "system_resources",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'app_resources': {
            'type': 'dict',
            'gslb_device_cfg': {
                'type': 'dict',
                'gslb_device_max': {
                    'type': 'int',
                },
                'gslb_device_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_geo_location_cfg': {
                'type': 'dict',
                'gslb_geo_location_max': {
                    'type': 'int',
                },
                'gslb_geo_location_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_ip_list_cfg': {
                'type': 'dict',
                'gslb_ip_list_max': {
                    'type': 'int',
                },
                'gslb_ip_list_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_policy_cfg': {
                'type': 'dict',
                'gslb_policy_max': {
                    'type': 'int',
                },
                'gslb_policy_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_service_cfg': {
                'type': 'dict',
                'gslb_service_max': {
                    'type': 'int',
                },
                'gslb_service_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_service_ip_cfg': {
                'type': 'dict',
                'gslb_service_ip_max': {
                    'type': 'int',
                },
                'gslb_service_ip_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_service_port_cfg': {
                'type': 'dict',
                'gslb_service_port_max': {
                    'type': 'int',
                },
                'gslb_service_port_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_site_cfg': {
                'type': 'dict',
                'gslb_site_max': {
                    'type': 'int',
                },
                'gslb_site_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_svc_group_cfg': {
                'type': 'dict',
                'gslb_svc_group_max': {
                    'type': 'int',
                },
                'gslb_svc_group_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_template_cfg': {
                'type': 'dict',
                'gslb_template_max': {
                    'type': 'int',
                },
                'gslb_template_min_guarantee': {
                    'type': 'int',
                }
            },
            'gslb_zone_cfg': {
                'type': 'dict',
                'gslb_zone_max': {
                    'type': 'int',
                },
                'gslb_zone_min_guarantee': {
                    'type': 'int',
                }
            },
            'health_monitor_cfg': {
                'type': 'dict',
                'health_monitor_max': {
                    'type': 'int',
                },
                'health_monitor_min_guarantee': {
                    'type': 'int',
                }
            },
            'real_port_cfg': {
                'type': 'dict',
                'real_port_max': {
                    'type': 'int',
                },
                'real_port_min_guarantee': {
                    'type': 'int',
                }
            },
            'real_server_cfg': {
                'type': 'dict',
                'real_server_max': {
                    'type': 'int',
                },
                'real_server_min_guarantee': {
                    'type': 'int',
                }
            },
            'service_group_cfg': {
                'type': 'dict',
                'service_group_max': {
                    'type': 'int',
                },
                'service_group_min_guarantee': {
                    'type': 'int',
                }
            },
            'virtual_server_cfg': {
                'type': 'dict',
                'virtual_server_max': {
                    'type': 'int',
                },
                'virtual_server_min_guarantee': {
                    'type': 'int',
                }
            },
            'threshold': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'network_resources': {
            'type': 'dict',
            'static_ipv4_route_cfg': {
                'type': 'dict',
                'static_ipv4_route_max': {
                    'type': 'int',
                },
                'static_ipv4_route_min_guarantee': {
                    'type': 'int',
                }
            },
            'static_ipv6_route_cfg': {
                'type': 'dict',
                'static_ipv6_route_max': {
                    'type': 'int',
                },
                'static_ipv6_route_min_guarantee': {
                    'type': 'int',
                }
            },
            'ipv4_acl_line_cfg': {
                'type': 'dict',
                'ipv4_acl_line_max': {
                    'type': 'int',
                },
                'ipv4_acl_line_min_guarantee': {
                    'type': 'int',
                }
            },
            'ipv6_acl_line_cfg': {
                'type': 'dict',
                'ipv6_acl_line_max': {
                    'type': 'int',
                },
                'ipv6_acl_line_min_guarantee': {
                    'type': 'int',
                }
            },
            'static_arp_cfg': {
                'type': 'dict',
                'static_arp_max': {
                    'type': 'int',
                },
                'static_arp_min_guarantee': {
                    'type': 'int',
                }
            },
            'static_neighbor_cfg': {
                'type': 'dict',
                'static_neighbor_max': {
                    'type': 'int',
                },
                'static_neighbor_min_guarantee': {
                    'type': 'int',
                }
            },
            'static_mac_cfg': {
                'type': 'dict',
                'static_mac_max': {
                    'type': 'int',
                },
                'static_mac_min_guarantee': {
                    'type': 'int',
                }
            },
            'object_group_cfg': {
                'type': 'dict',
                'object_group_max': {
                    'type': 'int',
                },
                'object_group_min_guarantee': {
                    'type': 'int',
                }
            },
            'object_group_clause_cfg': {
                'type': 'dict',
                'object_group_clause_max': {
                    'type': 'int',
                },
                'object_group_clause_min_guarantee': {
                    'type': 'int',
                }
            },
            'threshold': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'system_resources': {
            'type': 'dict',
            'bw_limit_cfg': {
                'type': 'dict',
                'bw_limit_max': {
                    'type': 'int',
                },
                'bw_limit_watermark_disable': {
                    'type': 'bool',
                }
            },
            'concurrent_session_limit_cfg': {
                'type': 'dict',
                'concurrent_session_limit_max': {
                    'type': 'int',
                }
            },
            'l4_session_limit_cfg': {
                'type': 'dict',
                'l4_session_limit_max': {
                    'type': 'str',
                },
                'l4_session_limit_min_guarantee': {
                    'type': 'str',
                }
            },
            'l4cps_limit_cfg': {
                'type': 'dict',
                'l4cps_limit_max': {
                    'type': 'int',
                }
            },
            'l7cps_limit_cfg': {
                'type': 'dict',
                'l7cps_limit_max': {
                    'type': 'int',
                }
            },
            'natcps_limit_cfg': {
                'type': 'dict',
                'natcps_limit_max': {
                    'type': 'int',
                }
            },
            'fwcps_limit_cfg': {
                'type': 'dict',
                'fwcps_limit_max': {
                    'type': 'int',
                }
            },
            'ssl_throughput_limit_cfg': {
                'type': 'dict',
                'ssl_throughput_limit_max': {
                    'type': 'int',
                },
                'ssl_throughput_limit_watermark_disable': {
                    'type': 'bool',
                }
            },
            'sslcps_limit_cfg': {
                'type': 'dict',
                'sslcps_limit_max': {
                    'type': 'int',
                }
            },
            'threshold': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-accounting/template/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/resource-accounting/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["template"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["template"].get(k) != v:
            change_results["changed"] = True
            config_changes["template"][k] = v

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
    payload = utils.build_json("template", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
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
