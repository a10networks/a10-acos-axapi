#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_management
description:
    - Management interface
author: A10 Networks
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    access_list:
        description:
        - "Field access_list"
        type: dict
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id"
                type: int
            acl_name:
                description:
                - "Apply an access list (Named Access List)"
                type: str
    duplexity:
        description:
        - "'Full'= Full; 'Half'= Half; 'auto'= Auto;"
        type: str
        required: False
    speed:
        description:
        - "'10'= 10 Mbs/sec; '100'= 100 Mbs/sec; '1000'= 1 Gb/sec; 'auto'= Auto Negotiate
          Speed;  (Interface Speed)"
        type: str
        required: False
    flow_control:
        description:
        - "Enable 802.3x flow control on full duplex port"
        type: bool
        required: False
    broadcast_rate_limit:
        description:
        - "Field broadcast_rate_limit"
        type: dict
        required: False
        suboptions:
            bcast_rate_limit_enable:
                description:
                - "Rate limit the l2 broadcast packet on mgmt port"
                type: bool
            rate:
                description:
                - "packets per second. Default is 500. (packets per second. Please specify an even
          number. Default is 500)"
                type: int
    mtu:
        description:
        - "Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))"
        type: int
        required: False
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            control_apps_use_mgmt_port:
                description:
                - "Control applications use management port"
                type: bool
            default_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    secondary_ip:
        description:
        - "Field secondary_ip"
        type: dict
        required: False
        suboptions:
            secondary_ip:
                description:
                - "Global IP configuration subcommands"
                type: bool
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            control_apps_use_mgmt_port:
                description:
                - "Control applications use management port"
                type: bool
            default_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    ipv6:
        description:
        - "Field ipv6"
        type: list
        required: False
        suboptions:
            ipv6_addr:
                description:
                - "Set the IPv6 address of an interface"
                type: str
            address_type:
                description:
                - "'link-local'= Configure an IPv6 link local address;"
                type: str
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
                type: str
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
                type: bool
            default_ipv6_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    action:
        description:
        - "'enable'= Enable Management Port; 'disable'= Disable Management Port;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'packets_input'= Input packets; 'bytes_input'= Input bytes;
          'received_broadcasts'= Received broadcasts; 'received_multicasts'= Received
          multicasts; 'received_unicasts'= Received unicasts; 'input_errors'= Input
          errors; 'crc'= CRC; 'frame'= Frames; 'input_err_short'= Runts;
          'input_err_long'= Giants; 'packets_output'= Output packets; 'bytes_output'=
          Output bytes; 'transmitted_broadcasts'= Transmitted broadcasts;
          'transmitted_multicasts'= Transmitted multicasts; 'transmitted_unicasts'=
          Transmitted unicasts; 'output_errors'= Output errors; 'collisions'= Collisions;"
                type: str
    lldp:
        description:
        - "Field lldp"
        type: dict
        required: False
        suboptions:
            enable_cfg:
                description:
                - "Field enable_cfg"
                type: dict
            notification_cfg:
                description:
                - "Field notification_cfg"
                type: dict
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
                type: dict
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
                type: dict
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
            interface:
                description:
                - "Field interface"
                type: str
            state:
                description:
                - "Field state"
                type: int
            line_protocol:
                description:
                - "Field line_protocol"
                type: str
            link_type:
                description:
                - "Field link_type"
                type: str
            mac:
                description:
                - "Field mac"
                type: str
            ipv4_addr:
                description:
                - "IP address"
                type: str
            ipv4_mask:
                description:
                - "IP subnet mask"
                type: str
            ipv4_default_gateway:
                description:
                - "IP gateway address"
                type: str
            ipv6_addr:
                description:
                - "Field ipv6_addr"
                type: str
            ipv6_prefix:
                description:
                - "Field ipv6_prefix"
                type: str
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
                type: str
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
                type: str
            ipv6_default_gateway:
                description:
                - "Field ipv6_default_gateway"
                type: str
            speed:
                description:
                - "Field speed"
                type: str
            duplexity:
                description:
                - "Field duplexity"
                type: str
            mtu:
                description:
                - "Field mtu"
                type: int
            flow_control:
                description:
                - "Field flow_control"
                type: int
            ipv4_acl:
                description:
                - "Field ipv4_acl"
                type: str
            ipv6_acl:
                description:
                - "Field ipv6_acl"
                type: str
            dhcp_enabled:
                description:
                - "Field dhcp_enabled"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_input:
                description:
                - "Input packets"
                type: str
            bytes_input:
                description:
                - "Input bytes"
                type: str
            received_broadcasts:
                description:
                - "Received broadcasts"
                type: str
            received_multicasts:
                description:
                - "Received multicasts"
                type: str
            received_unicasts:
                description:
                - "Received unicasts"
                type: str
            input_errors:
                description:
                - "Input errors"
                type: str
            crc:
                description:
                - "CRC"
                type: str
            frame:
                description:
                - "Frames"
                type: str
            input_err_short:
                description:
                - "Runts"
                type: str
            input_err_long:
                description:
                - "Giants"
                type: str
            packets_output:
                description:
                - "Output packets"
                type: str
            bytes_output:
                description:
                - "Output bytes"
                type: str
            transmitted_broadcasts:
                description:
                - "Transmitted broadcasts"
                type: str
            transmitted_multicasts:
                description:
                - "Transmitted multicasts"
                type: str
            transmitted_unicasts:
                description:
                - "Transmitted unicasts"
                type: str
            output_errors:
                description:
                - "Output errors"
                type: str
            collisions:
                description:
                - "Collisions"
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
AVAILABLE_PROPERTIES = ["access_list", "action", "broadcast_rate_limit", "duplexity", "flow_control", "ip", "ipv6", "lldp", "mtu", "oper", "sampling_enable", "secondary_ip", "speed", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'access_list': {
            'type': 'dict',
            'acl_id': {
                'type': 'int',
                },
            'acl_name': {
                'type': 'str',
                }
            },
        'duplexity': {
            'type': 'str',
            'choices': ['Full', 'Half', 'auto']
            },
        'speed': {
            'type': 'str',
            'choices': ['10', '100', '1000', 'auto']
            },
        'flow_control': {
            'type': 'bool',
            },
        'broadcast_rate_limit': {
            'type': 'dict',
            'bcast_rate_limit_enable': {
                'type': 'bool',
                },
            'rate': {
                'type': 'int',
                }
            },
        'mtu': {
            'type': 'int',
            },
        'ip': {
            'type': 'dict',
            'ipv4_address': {
                'type': 'str',
                },
            'ipv4_netmask': {
                'type': 'str',
                },
            'dhcp': {
                'type': 'bool',
                },
            'control_apps_use_mgmt_port': {
                'type': 'bool',
                },
            'default_gateway': {
                'type': 'str',
                }
            },
        'secondary_ip': {
            'type': 'dict',
            'secondary_ip': {
                'type': 'bool',
                },
            'ipv4_address': {
                'type': 'str',
                },
            'ipv4_netmask': {
                'type': 'str',
                },
            'dhcp': {
                'type': 'bool',
                },
            'control_apps_use_mgmt_port': {
                'type': 'bool',
                },
            'default_gateway': {
                'type': 'str',
                }
            },
        'ipv6': {
            'type': 'list',
            'ipv6_addr': {
                'type': 'str',
                },
            'address_type': {
                'type': 'str',
                'choices': ['link-local']
                },
            'v6_acl_name': {
                'type': 'str',
                },
            'inbound': {
                'type': 'bool',
                },
            'default_ipv6_gateway': {
                'type': 'str',
                }
            },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type': 'str',
                'choices': ['all', 'packets_input', 'bytes_input', 'received_broadcasts', 'received_multicasts', 'received_unicasts', 'input_errors', 'crc', 'frame', 'input_err_short', 'input_err_long', 'packets_output', 'bytes_output', 'transmitted_broadcasts', 'transmitted_multicasts', 'transmitted_unicasts', 'output_errors', 'collisions']
                }
            },
        'lldp': {
            'type': 'dict',
            'enable_cfg': {
                'type': 'dict',
                'rt_enable': {
                    'type': 'bool',
                    },
                'rx': {
                    'type': 'bool',
                    },
                'tx': {
                    'type': 'bool',
                    }
                },
            'notification_cfg': {
                'type': 'dict',
                'notification': {
                    'type': 'bool',
                    },
                'notif_enable': {
                    'type': 'bool',
                    }
                },
            'tx_dot1_cfg': {
                'type': 'dict',
                'tx_dot1_tlvs': {
                    'type': 'bool',
                    },
                'link_aggregation': {
                    'type': 'bool',
                    },
                'vlan': {
                    'type': 'bool',
                    }
                },
            'tx_tlvs_cfg': {
                'type': 'dict',
                'tx_tlvs': {
                    'type': 'bool',
                    },
                'exclude': {
                    'type': 'bool',
                    },
                'management_address': {
                    'type': 'bool',
                    },
                'port_description': {
                    'type': 'bool',
                    },
                'system_capabilities': {
                    'type': 'bool',
                    },
                'system_description': {
                    'type': 'bool',
                    },
                'system_name': {
                    'type': 'bool',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'interface': {
                'type': 'str',
                },
            'state': {
                'type': 'int',
                },
            'line_protocol': {
                'type': 'str',
                },
            'link_type': {
                'type': 'str',
                'choices': ['GigabitEthernet', '10Gig', '40Gig']
                },
            'mac': {
                'type': 'str',
                },
            'ipv4_addr': {
                'type': 'str',
                },
            'ipv4_mask': {
                'type': 'str',
                },
            'ipv4_default_gateway': {
                'type': 'str',
                },
            'ipv6_addr': {
                'type': 'str',
                },
            'ipv6_prefix': {
                'type': 'str',
                },
            'ipv6_link_local': {
                'type': 'str',
                },
            'ipv6_link_local_prefix': {
                'type': 'str',
                },
            'ipv6_default_gateway': {
                'type': 'str',
                },
            'speed': {
                'type': 'str',
                },
            'duplexity': {
                'type': 'str',
                },
            'mtu': {
                'type': 'int',
                },
            'flow_control': {
                'type': 'int',
                },
            'ipv4_acl': {
                'type': 'str',
                },
            'ipv6_acl': {
                'type': 'str',
                },
            'dhcp_enabled': {
                'type': 'int',
                }
            },
        'stats': {
            'type': 'dict',
            'packets_input': {
                'type': 'str',
                },
            'bytes_input': {
                'type': 'str',
                },
            'received_broadcasts': {
                'type': 'str',
                },
            'received_multicasts': {
                'type': 'str',
                },
            'received_unicasts': {
                'type': 'str',
                },
            'input_errors': {
                'type': 'str',
                },
            'crc': {
                'type': 'str',
                },
            'frame': {
                'type': 'str',
                },
            'input_err_short': {
                'type': 'str',
                },
            'input_err_long': {
                'type': 'str',
                },
            'packets_output': {
                'type': 'str',
                },
            'bytes_output': {
                'type': 'str',
                },
            'transmitted_broadcasts': {
                'type': 'str',
                },
            'transmitted_multicasts': {
                'type': 'str',
                },
            'transmitted_unicasts': {
                'type': 'str',
                },
            'output_errors': {
                'type': 'str',
                },
            'collisions': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/management"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/management"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["management"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["management"].get(k) != v:
            change_results["changed"] = True
            config_changes["management"][k] = v

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
    payload = utils.build_json("management", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


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

        if state == 'noop':
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["management"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["management-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["management"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["management"]["stats"] if info != "NotFound" else info
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
