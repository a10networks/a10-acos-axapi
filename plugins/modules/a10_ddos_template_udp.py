#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_template_udp
description:
    - UDP template configuration
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
    name:
        description:
        - "DDOS UDP Template Name"
        type: str
        required: True
    age:
        description:
        - "Configure session age(in minutes) for UDP sessions"
        type: int
        required: False
    per_conn_pkt_rate_limit:
        description:
        - "Packet rate limit per connection per rate-interval"
        type: int
        required: False
    per_conn_rate_interval:
        description:
        - "'100ms'= 100ms; '1sec'= 1sec;"
        type: str
        required: False
    tunnel_encap:
        description:
        - "Field tunnel_encap"
        type: dict
        required: False
        suboptions:
            ip_encap:
                description:
                - "Enable Tunnel encapsulation using IP in IP"
                type: bool
            always:
                description:
                - "Field always"
                type: dict
            gre_encap:
                description:
                - "Enable Tunnel encapsulation using GRE"
                type: bool
            gre_always:
                description:
                - "Field gre_always"
                type: dict
    spoof_detect_cfg:
        description:
        - "Field spoof_detect_cfg"
        type: dict
        required: False
        suboptions:
            spoof_detect:
                description:
                - "Force client to retry on udp"
                type: bool
            min_retry_gap_interval:
                description:
                - "'100ms'= 100ms; '1sec'= 1sec;"
                type: str
            spoof_detect_retry_timeout_val_only:
                description:
                - "timeout in seconds"
                type: int
            min_retry_gap:
                description:
                - "Optional minimum gap between 2 UDP packets for spoof-detect pass, unit is
          specified by min-retry-gap-interval"
                type: int
            spoof_detect_retry_timeout:
                description:
                - "timeout in seconds"
                type: int
    drop_known_resp_src_port_cfg:
        description:
        - "Field drop_known_resp_src_port_cfg"
        type: dict
        required: False
        suboptions:
            drop_known_resp_src_port:
                description:
                - "Drop well-known if src-port is less than 1024"
                type: bool
            exclude_src_resp_port:
                description:
                - "excluding src port equal destination port"
                type: bool
    drop_ntp_monlist:
        description:
        - "Drop NTP monlist request/response"
        type: bool
        required: False
    token_authentication:
        description:
        - "Enable Token Authentication"
        type: bool
        required: False
    token_authentication_hw_assist_disable:
        description:
        - "token-authentication disable hardware assistance"
        type: bool
        required: False
    token_authentication_salt_prefix:
        description:
        - "token-authentication salt-prefix"
        type: bool
        required: False
    token_authentication_salt_prefix_curr:
        description:
        - "Field token_authentication_salt_prefix_curr"
        type: int
        required: False
    token_authentication_salt_prefix_prev:
        description:
        - "Field token_authentication_salt_prefix_prev"
        type: int
        required: False
    token_authentication_formula:
        description:
        - "'md5_Salt-SrcIp-SrcPort-DstIp-DstPort'= md5 of Salt-SrcIp-SrcPort-DstIp-
          DstPort; 'md5_Salt-DstIp-DstPort'= md5 of Salt-DstIp-DstPort; 'md5_Salt-SrcIp-
          DstIp'= md5 of Salt-SrcIp-DstIp; 'md5_Salt-SrcPort-DstPort'= md5 of Salt-
          SrcPort-DstPort; 'md5_Salt-UintDstIp-DstPort'= Using the uint value of IP for
          md5 of Salt-DstIp-DstPort; 'sha1_Salt-SrcIp-SrcPort-DstIp-DstPort'= sha1 of
          Salt-SrcIp-SrcPort-DstIp-DstPort; 'sha1_Salt-DstIp-DstPort'= sha1 of Salt-
          DstIp-DstPort; 'sha1_Salt-SrcIp-DstIp'= sha1 of Salt-SrcIp-DstIp; 'sha1_Salt-
          SrcPort-DstPort'= sha1 of Salt-SrcPort-DstPort; 'sha1_Salt-UintDstIp-DstPort'=
          Using the uint value of IP for sha1 of Salt-DstIp-DstPort;"
        type: str
        required: False
    previous_salt_timeout:
        description:
        - "Token-Authentication previous salt-prefix timeout in minutes, default is 1 min"
        type: int
        required: False
    token_authentication_public_address:
        description:
        - "The server public IP address"
        type: bool
        required: False
    public_ipv4_addr:
        description:
        - "IP address"
        type: str
        required: False
    public_ipv6_addr:
        description:
        - "IPV6 address"
        type: str
        required: False
    max_payload_size:
        description:
        - "Maximum UDP payload size for each single packet"
        type: int
        required: False
    min_payload_size:
        description:
        - "Minimum UDP payload size for each single packet"
        type: int
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
    filter_list:
        description:
        - "Field filter_list"
        type: list
        required: False
        suboptions:
            udp_filter_seq:
                description:
                - "Sequence number"
                type: int
            udp_filter_regex:
                description:
                - "Regex Expression"
                type: str
            byte_offset_filter:
                description:
                - "Filter Expression using Berkeley Packet Filter syntax"
                type: str
            udp_filter_unmatched:
                description:
                - "action taken when it does not match"
                type: bool
            udp_filter_action:
                description:
                - "'blacklist-src'= Also blacklist the source when action is taken; 'whitelist-
          src'= Whitelist the source after filter passes, packets are dropped until then;
          'count-only'= Take no action and continue processing the next filter;"
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
AVAILABLE_PROPERTIES = [
    "age", "drop_known_resp_src_port_cfg", "drop_ntp_monlist", "filter_list", "max_payload_size", "min_payload_size", "name", "per_conn_pkt_rate_limit", "per_conn_rate_interval", "previous_salt_timeout", "public_ipv4_addr", "public_ipv6_addr", "spoof_detect_cfg", "token_authentication", "token_authentication_formula",
    "token_authentication_hw_assist_disable", "token_authentication_public_address", "token_authentication_salt_prefix", "token_authentication_salt_prefix_curr", "token_authentication_salt_prefix_prev", "tunnel_encap", "user_tag", "uuid",
    ]


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
        'name': {
            'type': 'str',
            'required': True,
            },
        'age': {
            'type': 'int',
            },
        'per_conn_pkt_rate_limit': {
            'type': 'int',
            },
        'per_conn_rate_interval': {
            'type': 'str',
            'choices': ['100ms', '1sec']
            },
        'tunnel_encap': {
            'type': 'dict',
            'ip_encap': {
                'type': 'bool',
                },
            'always': {
                'type': 'dict',
                'ipv4_addr': {
                    'type': 'str',
                    },
                'preserve_src_ipv4': {
                    'type': 'bool',
                    },
                'ipv6_addr': {
                    'type': 'str',
                    },
                'preserve_src_ipv6': {
                    'type': 'bool',
                    }
                },
            'gre_encap': {
                'type': 'bool',
                },
            'gre_always': {
                'type': 'dict',
                'gre_ipv4': {
                    'type': 'str',
                    },
                'key_ipv4': {
                    'type': 'str',
                    },
                'preserve_src_ipv4_gre': {
                    'type': 'bool',
                    },
                'gre_ipv6': {
                    'type': 'str',
                    },
                'key_ipv6': {
                    'type': 'str',
                    },
                'preserve_src_ipv6_gre': {
                    'type': 'bool',
                    }
                }
            },
        'spoof_detect_cfg': {
            'type': 'dict',
            'spoof_detect': {
                'type': 'bool',
                },
            'min_retry_gap_interval': {
                'type': 'str',
                'choices': ['100ms', '1sec']
                },
            'spoof_detect_retry_timeout_val_only': {
                'type': 'int',
                },
            'min_retry_gap': {
                'type': 'int',
                },
            'spoof_detect_retry_timeout': {
                'type': 'int',
                }
            },
        'drop_known_resp_src_port_cfg': {
            'type': 'dict',
            'drop_known_resp_src_port': {
                'type': 'bool',
                },
            'exclude_src_resp_port': {
                'type': 'bool',
                }
            },
        'drop_ntp_monlist': {
            'type': 'bool',
            },
        'token_authentication': {
            'type': 'bool',
            },
        'token_authentication_hw_assist_disable': {
            'type': 'bool',
            },
        'token_authentication_salt_prefix': {
            'type': 'bool',
            },
        'token_authentication_salt_prefix_curr': {
            'type': 'int',
            },
        'token_authentication_salt_prefix_prev': {
            'type': 'int',
            },
        'token_authentication_formula': {
            'type': 'str',
            'choices': ['md5_Salt-SrcIp-SrcPort-DstIp-DstPort', 'md5_Salt-DstIp-DstPort', 'md5_Salt-SrcIp-DstIp', 'md5_Salt-SrcPort-DstPort', 'md5_Salt-UintDstIp-DstPort', 'sha1_Salt-SrcIp-SrcPort-DstIp-DstPort', 'sha1_Salt-DstIp-DstPort', 'sha1_Salt-SrcIp-DstIp', 'sha1_Salt-SrcPort-DstPort', 'sha1_Salt-UintDstIp-DstPort']
            },
        'previous_salt_timeout': {
            'type': 'int',
            },
        'token_authentication_public_address': {
            'type': 'bool',
            },
        'public_ipv4_addr': {
            'type': 'str',
            },
        'public_ipv6_addr': {
            'type': 'str',
            },
        'max_payload_size': {
            'type': 'int',
            },
        'min_payload_size': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'filter_list': {
            'type': 'list',
            'udp_filter_seq': {
                'type': 'int',
                'required': True,
                },
            'udp_filter_regex': {
                'type': 'str',
                },
            'byte_offset_filter': {
                'type': 'str',
                },
            'udp_filter_unmatched': {
                'type': 'bool',
                },
            'udp_filter_action': {
                'type': 'str',
                'choices': ['blacklist-src', 'whitelist-src', 'count-only']
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
    url_base = "/axapi/v3/ddos/template/udp/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/template/udp"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["udp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["udp"].get(k) != v:
            change_results["changed"] = True
            config_changes["udp"][k] = v

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
    payload = utils.build_json("udp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["udp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["udp-list"] if info != "NotFound" else info
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
