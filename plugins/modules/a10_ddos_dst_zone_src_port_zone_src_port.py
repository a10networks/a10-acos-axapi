#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone_src_port_zone_src_port
description:
    - DDOS Port & Protocol configuration
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
    zone_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_num:
        description:
        - "Source Port Number"
        type: int
        required: True
    protocol:
        description:
        - "'dns-udp'= DNS-UDP Port; 'dns-tcp'= DNS-TCP Port; 'udp'= UDP port; 'tcp'= TCP
          Port;"
        type: str
        required: True
    deny:
        description:
        - "Blacklist and Drop all incoming packets for protocol"
        type: bool
        required: False
    glid_cfg:
        description:
        - "Field glid_cfg"
        type: dict
        required: False
        suboptions:
            glid:
                description:
                - "Global limit ID"
                type: str
            glid_action:
                description:
                - "'drop'= Drop packets for glid exceed (Default); 'ignore'= Do nothing for glid
          exceed;"
                type: str
    outbound_src_tracking:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    zone_template:
        description:
        - "Field zone_template"
        type: dict
        required: False
        suboptions:
            src_udp:
                description:
                - "DDOS udp src template"
                type: str
            src_tcp:
                description:
                - "DDOS tcp src template"
                type: str
            src_dns:
                description:
                - "DDOS dns src template"
                type: str
    default_action_list:
        description:
        - "Configure default-action-list"
        type: str
        required: False
    set_counter_base_val:
        description:
        - "Set T2 counter value of current context to specified value"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    port_ind:
        description:
        - "Field port_ind"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    level_list:
        description:
        - "Field level_list"
        type: list
        required: False
        suboptions:
            level_num:
                description:
                - "'0'= Default policy level; '1'= Policy level 1;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            indicator_list:
                description:
                - "Field indicator_list"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ddos_entry_list:
                description:
                - "Field ddos_entry_list"
                type: list
            entry_displayed_count:
                description:
                - "Field entry_displayed_count"
                type: int
            service_displayed_count:
                description:
                - "Field service_displayed_count"
                type: int
            reporting_status:
                description:
                - "Field reporting_status"
                type: int
            sources:
                description:
                - "Field sources"
                type: bool
            sources_all_entries:
                description:
                - "Field sources_all_entries"
                type: bool
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            ipv6:
                description:
                - "Field ipv6"
                type: str
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: bool
            port_num:
                description:
                - "Source Port Number"
                type: int
            protocol:
                description:
                - "'dns-udp'= DNS-UDP Port; 'dns-tcp'= DNS-TCP Port; 'udp'= UDP port; 'tcp'= TCP
          Port;"
                type: str
            port_ind:
                description:
                - "Field port_ind"
                type: dict

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
AVAILABLE_PROPERTIES = ["default_action_list", "deny", "glid_cfg", "level_list", "oper", "outbound_src_tracking", "port_ind", "port_num", "protocol", "set_counter_base_val", "uuid", "zone_template", ]


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
        'port_num': {
            'type': 'int',
            'required': True,
            },
        'protocol': {
            'type': 'str',
            'required': True,
            'choices': ['dns-udp', 'dns-tcp', 'udp', 'tcp']
            },
        'deny': {
            'type': 'bool',
            },
        'glid_cfg': {
            'type': 'dict',
            'glid': {
                'type': 'str',
                },
            'glid_action': {
                'type': 'str',
                'choices': ['drop', 'ignore']
                }
            },
        'outbound_src_tracking': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'zone_template': {
            'type': 'dict',
            'src_udp': {
                'type': 'str',
                },
            'src_tcp': {
                'type': 'str',
                },
            'src_dns': {
                'type': 'str',
                }
            },
        'default_action_list': {
            'type': 'str',
            },
        'set_counter_base_val': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'port_ind': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'level_list': {
            'type': 'list',
            'level_num': {
                'type': 'str',
                'required': True,
                'choices': ['0', '1']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'indicator_list': {
                'type': 'list',
                'ntype': {
                    'type': 'str',
                    'required': True,
                    'choices': ['pkt-rate', 'bit-rate']
                    },
                'zone_threshold_num': {
                    'type': 'int',
                    },
                'zone_threshold_large_num': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'bw_state': {
                    'type': 'str',
                    },
                'is_auth_passed': {
                    'type': 'str',
                    },
                'level': {
                    'type': 'int',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'is_connections_exceed': {
                    'type': 'int',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'is_connection_rate_exceed': {
                    'type': 'int',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'is_packet_rate_exceed': {
                    'type': 'int',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'is_kBit_rate_exceed': {
                    'type': 'int',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'is_frag_packet_rate_exceed': {
                    'type': 'int',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'current_app_stat1': {
                    'type': 'str',
                    },
                'is_app_stat1_exceed': {
                    'type': 'int',
                    },
                'app_stat1_limit': {
                    'type': 'str',
                    },
                'current_app_stat2': {
                    'type': 'str',
                    },
                'is_app_stat2_exceed': {
                    'type': 'int',
                    },
                'app_stat2_limit': {
                    'type': 'str',
                    },
                'current_app_stat3': {
                    'type': 'str',
                    },
                'is_app_stat3_exceed': {
                    'type': 'int',
                    },
                'app_stat3_limit': {
                    'type': 'str',
                    },
                'current_app_stat4': {
                    'type': 'str',
                    },
                'is_app_stat4_exceed': {
                    'type': 'int',
                    },
                'app_stat4_limit': {
                    'type': 'str',
                    },
                'current_app_stat5': {
                    'type': 'str',
                    },
                'is_app_stat5_exceed': {
                    'type': 'int',
                    },
                'app_stat5_limit': {
                    'type': 'str',
                    },
                'current_app_stat6': {
                    'type': 'str',
                    },
                'is_app_stat6_exceed': {
                    'type': 'int',
                    },
                'app_stat6_limit': {
                    'type': 'str',
                    },
                'current_app_stat7': {
                    'type': 'str',
                    },
                'is_app_stat7_exceed': {
                    'type': 'int',
                    },
                'app_stat7_limit': {
                    'type': 'str',
                    },
                'current_app_stat8': {
                    'type': 'str',
                    },
                'is_app_stat8_exceed': {
                    'type': 'int',
                    },
                'app_stat8_limit': {
                    'type': 'str',
                    },
                'age': {
                    'type': 'int',
                    },
                'lockup_time': {
                    'type': 'int',
                    },
                'dynamic_entry_count': {
                    'type': 'str',
                    },
                'dynamic_entry_limit': {
                    'type': 'str',
                    },
                'dynamic_entry_warn_state': {
                    'type': 'str',
                    },
                'sflow_source_id': {
                    'type': 'int',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'entry_displayed_count': {
                'type': 'int',
                },
            'service_displayed_count': {
                'type': 'int',
                },
            'reporting_status': {
                'type': 'int',
                },
            'sources': {
                'type': 'bool',
                },
            'sources_all_entries': {
                'type': 'bool',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'ipv6': {
                'type': 'str',
                },
            'hw_blacklisted': {
                'type': 'bool',
                },
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-udp', 'dns-tcp', 'udp', 'tcp']
                },
            'port_ind': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'indicators': {
                        'type': 'list',
                        'indicator_name': {
                            'type': 'str',
                            },
                        'indicator_index': {
                            'type': 'int',
                            },
                        'rate': {
                            'type': 'str',
                            },
                        'indicator_cfg': {
                            'type': 'list',
                            'level': {
                                'type': 'int',
                                },
                            'zone_threshold': {
                                'type': 'str',
                                },
                            'source_threshold': {
                                'type': 'str',
                                }
                            }
                        },
                    'detection_data_source': {
                        'type': 'str',
                        },
                    'current_level': {
                        'type': 'str',
                        },
                    'details': {
                        'type': 'bool',
                        }
                    }
                }
            }
        })
    # Parent keys
    rv.update(dict(zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/src-port/zone-src-port/{port_num}+{protocol}"

    f_dict = {}
    if '/' in str(module.params["port_num"]):
        f_dict["port_num"] = module.params["port_num"].replace("/", "%2F")
    else:
        f_dict["port_num"] = module.params["port_num"]
    if '/' in str(module.params["protocol"]):
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["zone_name"]:
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/src-port/zone-src-port/"

    f_dict = {}
    f_dict["port_num"] = ""
    f_dict["protocol"] = ""
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["zone-src-port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["zone-src-port"].get(k) != v:
            change_results["changed"] = True
            config_changes["zone-src-port"][k] = v

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
    payload = utils.build_json("zone-src-port", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["zone-src-port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["zone-src-port-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["zone-src-port"]["oper"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
