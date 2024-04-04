#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_dynamic_entry_overflow_policy
description:
    - Configure IP/IPv6 Policy Used When Dynamic Dst Entry Count overflows
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
    default_address_type:
        description:
        - "'ip'= ip; 'ipv6'= ipv6;"
        type: str
        required: True
    exceed_log_dep_cfg:
        description:
        - "Field exceed_log_dep_cfg"
        type: dict
        required: False
        suboptions:
            exceed_log_enable:
                description:
                - "(Deprecated)Enable logging of limit exceed drop's"
                type: bool
            log_with_sflow_dep:
                description:
                - "Turn on sflow sample with log"
                type: bool
    exceed_log_cfg:
        description:
        - "Field exceed_log_cfg"
        type: dict
        required: False
        suboptions:
            log_enable:
                description:
                - "Enable logging of limit exceed drop's"
                type: bool
            with_sflow_sample:
                description:
                - "Turn on sflow sample with log"
                type: bool
    drop_disable:
        description:
        - "Disable certain drops during packet processing"
        type: bool
        required: False
    drop_disable_fwd_immediate:
        description:
        - "Immediately forward L4 drops"
        type: bool
        required: False
    log_periodic:
        description:
        - "Enable periodic log while event is continuing"
        type: bool
        required: False
    inbound_forward_dscp:
        description:
        - "To set dscp value for inbound packets (DSCP Value for the clear traffic
          marking)"
        type: int
        required: False
    outbound_forward_dscp:
        description:
        - "To set dscp value for outbound"
        type: int
        required: False
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            logging:
                description:
                - "DDOS logging template"
                type: str
    glid:
        description:
        - "Global limit ID"
        type: str
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
    l4_type_list:
        description:
        - "Field l4_type_list"
        type: list
        required: False
        suboptions:
            protocol:
                description:
                - "'tcp'= tcp; 'udp'= udp; 'icmp'= icmp; 'other'= other;"
                type: str
            glid:
                description:
                - "Global limit ID"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            max_rexmit_syn_per_flow:
                description:
                - "Maximum number of re-transmit SYN per flow. Exceed action set to Drop"
                type: int
            syn_auth:
                description:
                - "'send-rst'= Send RST to client upon client ACK; 'force-rst-by-ack'= Force
          client RST via the use of ACK; 'force-rst-by-synack'= Force client RST via the
          use of bad SYN|ACK; 'disable'= Disable TCP SYN Authentication;"
                type: str
            syn_cookie:
                description:
                - "Enable SYN Cookie"
                type: bool
            tcp_reset_client:
                description:
                - "Send reset to client when rate exceeds or session ages out"
                type: bool
            tcp_reset_server:
                description:
                - "Send reset to server when rate exceeds or session ages out"
                type: bool
            drop_on_no_port_match:
                description:
                - "'disable'= disable; 'enable'= enable;"
                type: str
            stateful:
                description:
                - "Enable stateful tracking of sessions (Default is stateless)"
                type: bool
            tunnel_decap:
                description:
                - "Field tunnel_decap"
                type: dict
            tunnel_rate_limit:
                description:
                - "Field tunnel_rate_limit"
                type: dict
            drop_frag_pkt:
                description:
                - "Drop fragmented packets"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'dns-tcp'= dns-tcp; 'dns-udp'= dns-udp; 'http'= http; 'tcp'= tcp; 'udp'= udp;
          'ssl-l4'= ssl-l4; 'sip-udp'= sip-udp; 'sip-tcp'= sip-tcp;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            template:
                description:
                - "Field template"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    src_port_list:
        description:
        - "Field src_port_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'udp'= udp; 'tcp'= tcp;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            template:
                description:
                - "Field template"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    ip_proto_list:
        description:
        - "Field ip_proto_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Protocol Number"
                type: int
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            template:
                description:
                - "Field template"
                type: dict
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
AVAILABLE_PROPERTIES = ["default_address_type", "drop_disable", "drop_disable_fwd_immediate", "exceed_log_cfg", "exceed_log_dep_cfg", "glid", "inbound_forward_dscp", "ip_proto_list", "l4_type_list", "log_periodic", "outbound_forward_dscp", "port_list", "src_port_list", "template", "user_tag", "uuid", ]


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
        'default_address_type': {
            'type': 'str',
            'required': True,
            'choices': ['ip', 'ipv6']
            },
        'exceed_log_dep_cfg': {
            'type': 'dict',
            'exceed_log_enable': {
                'type': 'bool',
                },
            'log_with_sflow_dep': {
                'type': 'bool',
                }
            },
        'exceed_log_cfg': {
            'type': 'dict',
            'log_enable': {
                'type': 'bool',
                },
            'with_sflow_sample': {
                'type': 'bool',
                }
            },
        'drop_disable': {
            'type': 'bool',
            },
        'drop_disable_fwd_immediate': {
            'type': 'bool',
            },
        'log_periodic': {
            'type': 'bool',
            },
        'inbound_forward_dscp': {
            'type': 'int',
            },
        'outbound_forward_dscp': {
            'type': 'int',
            },
        'template': {
            'type': 'dict',
            'logging': {
                'type': 'str',
                }
            },
        'glid': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'l4_type_list': {
            'type': 'list',
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp', 'icmp', 'other']
                },
            'glid': {
                'type': 'str',
                },
            'deny': {
                'type': 'bool',
                },
            'max_rexmit_syn_per_flow': {
                'type': 'int',
                },
            'syn_auth': {
                'type': 'str',
                'choices': ['send-rst', 'force-rst-by-ack', 'force-rst-by-synack', 'disable']
                },
            'syn_cookie': {
                'type': 'bool',
                },
            'tcp_reset_client': {
                'type': 'bool',
                },
            'tcp_reset_server': {
                'type': 'bool',
                },
            'drop_on_no_port_match': {
                'type': 'str',
                'choices': ['disable', 'enable']
                },
            'stateful': {
                'type': 'bool',
                },
            'tunnel_decap': {
                'type': 'dict',
                'ip_decap': {
                    'type': 'bool',
                    },
                'gre_decap': {
                    'type': 'bool',
                    },
                'key_cfg': {
                    'type': 'list',
                    'key': {
                        'type': 'str',
                        }
                    }
                },
            'tunnel_rate_limit': {
                'type': 'dict',
                'ip_rate_limit': {
                    'type': 'bool',
                    },
                'gre_rate_limit': {
                    'type': 'bool',
                    }
                },
            'drop_frag_pkt': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'port_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'template': {
                'type': 'dict',
                'dns': {
                    'type': 'str',
                    },
                'http': {
                    'type': 'str',
                    },
                'ssl_l4': {
                    'type': 'str',
                    },
                'sip': {
                    'type': 'str',
                    },
                'tcp': {
                    'type': 'str',
                    },
                'udp': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'src_port_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['udp', 'tcp']
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'template': {
                'type': 'dict',
                'src_udp': {
                    'type': 'str',
                    },
                'src_tcp': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'ip_proto_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'template': {
                'type': 'dict',
                'other': {
                    'type': 'str',
                    }
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
    url_base = "/axapi/v3/ddos/dst/dynamic-entry-overflow-policy/{default_address_type}"

    f_dict = {}
    if '/' in str(module.params["default_address_type"]):
        f_dict["default_address_type"] = module.params["default_address_type"].replace("/", "%2F")
    else:
        f_dict["default_address_type"] = module.params["default_address_type"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/dynamic-entry-overflow-policy"

    f_dict = {}
    f_dict["default_address_type"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dynamic-entry-overflow-policy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dynamic-entry-overflow-policy"].get(k) != v:
            change_results["changed"] = True
            config_changes["dynamic-entry-overflow-policy"][k] = v

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
    payload = utils.build_json("dynamic-entry-overflow-policy", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dynamic-entry-overflow-policy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dynamic-entry-overflow-policy-list"] if info != "NotFound" else info
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
