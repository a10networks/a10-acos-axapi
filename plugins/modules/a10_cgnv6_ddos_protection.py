#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_ddos_protection
description:
    - Configure CGNV6 DDoS Protection
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
    toggle:
        description:
        - "'enable'= Enable CGNV6 NAT pool DDoS protection (default); 'disable'= Disable
          CGNV6 NAT pool DDoS protection;"
        type: str
        required: False
    logging_action:
        description:
        - "'enable'= enable CGN DDoS protection logging; 'disable'= Disable both local &
          remote CGN DDoS protection logging;"
        type: str
        required: False
    enable_action:
        description:
        - "'local'= Enable local logs only; 'remote'= Enable logging to remote server &
          IPFIX; 'both'= Enable both local & remote logs;"
        type: str
        required: False
    packets_per_second:
        description:
        - "Field packets_per_second"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Configure packets-per-second threshold per IP(default 3000000)"
                type: int
            action:
                description:
                - "Field action"
                type: dict
            tcp:
                description:
                - "Configure packets-per-second threshold per TCP port (default= 3000)"
                type: int
            tcp_action:
                description:
                - "Field tcp_action"
                type: dict
            udp:
                description:
                - "Configure packets-per-second threshold per UDP port (default= 3000)"
                type: int
            udp_action:
                description:
                - "Field udp_action"
                type: dict
            other:
                description:
                - "Configure packets-per-second threshold for other L4 protocols(default 10000)"
                type: int
            other_action:
                description:
                - "Field other_action"
                type: dict
            include_existing_session:
                description:
                - "Count traffic associated with existing session into the packets-per-second
          (Default= Disabled)"
                type: bool
    syn_cookie:
        description:
        - "Field syn_cookie"
        type: dict
        required: False
        suboptions:
            syn_cookie_enable:
                description:
                - "Enable CGNv6 Syn-Cookie Protection"
                type: bool
            syn_cookie_on_threshold:
                description:
                - "on-threshold for Syn-cookie (Decimal number)"
                type: int
            syn_cookie_on_timeout:
                description:
                - "on-timeout for Syn-cookie (Timeout in seconds, default is 120 seconds (2
          minutes))"
                type: int
    max_hw_entries:
        description:
        - "Configure maximum HW entries"
        type: int
        required: False
    zone:
        description:
        - "Disable NAT IP based on DDoS zone name set in BGP"
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
                - "'all'= all; 'l3_entry_added'= L3 Entry Added; 'l3_entry_deleted'= L3 Entry
          Deleted; 'l3_entry_added_to_bgp'= L3 Entry added to BGP;
          'l3_entry_removed_from_bgp'= Entry removed from BGP; 'l3_entry_added_to_hw'= L3
          Entry added to HW; 'l3_entry_removed_from_hw'= L3 Entry removed from HW;
          'l3_entry_too_many'= L3 Too many entries; 'l3_entry_match_drop'= L3 Entry match
          drop; 'l3_entry_match_drop_hw'= L3 HW entry match drop;
          'l3_entry_drop_max_hw_exceeded'= L3 Entry Drop due to HW Limit Exceeded;
          'l4_entry_added'= L4 Entry added; 'l4_entry_deleted'= L4 Entry deleted;
          'l4_entry_added_to_hw'= L4 Entry added to HW; 'l4_entry_removed_from_hw'= L4
          Entry removed from HW; 'l4_hw_out_of_entries'= HW out of L4 entries;
          'l4_entry_match_drop'= L4 Entry match drop; 'l4_entry_match_drop_hw'= L4 HW
          Entry match drop; 'l4_entry_drop_max_hw_exceeded'= L4 Entry Drop due to HW
          Limit Exceeded; 'l4_entry_list_alloc'= L4 Entry list alloc;
          'l4_entry_list_free'= L4 Entry list free; 'l4_entry_list_alloc_failure'= L4
          Entry list alloc failures; 'ip_node_alloc'= Node alloc; 'ip_node_free'= Node
          free; 'ip_node_alloc_failure'= Node alloc failures; 'ip_port_block_alloc'= Port
          block alloc; 'ip_port_block_free'= Port block free;
          'ip_port_block_alloc_failure'= Port block alloc failure;
          'ip_other_block_alloc'= Other block alloc; 'ip_other_block_free'= Other block
          free; 'ip_other_block_alloc_failure'= Other block alloc failure;
          'entry_added_shadow'= Entry added shadow; 'entry_invalidated'= Entry
          invalidated; 'l3_entry_add_to_bgp_failure'= L3 Entry BGP add failures;
          'l3_entry_remove_from_bgp_failure'= L3 entry BGP remove failures;
          'l3_entry_add_to_hw_failure'= L3 entry HW add failure;
          'syn_cookie_syn_ack_sent'= SYN cookie SYN ACK sent;
          'syn_cookie_verification_passed'= SYN cookie verification passed;
          'syn_cookie_verification_failed'= SYN cookie verification failed;
          'syn_cookie_conn_setup_failed'= SYN cookie connection setup failed;"
                type: str
    l4_entries:
        description:
        - "Field l4_entries"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ip_entries:
        description:
        - "Field ip_entries"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    disable_nat_ip_by_bgp:
        description:
        - "Field disable_nat_ip_by_bgp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            l3_entry_added:
                description:
                - "L3 Entry Added"
                type: str
            l3_entry_deleted:
                description:
                - "L3 Entry Deleted"
                type: str
            l3_entry_added_to_bgp:
                description:
                - "L3 Entry added to BGP"
                type: str
            l3_entry_removed_from_bgp:
                description:
                - "Entry removed from BGP"
                type: str
            l3_entry_added_to_hw:
                description:
                - "L3 Entry added to HW"
                type: str
            l3_entry_removed_from_hw:
                description:
                - "L3 Entry removed from HW"
                type: str
            l3_entry_too_many:
                description:
                - "L3 Too many entries"
                type: str
            l3_entry_match_drop:
                description:
                - "L3 Entry match drop"
                type: str
            l3_entry_match_drop_hw:
                description:
                - "L3 HW entry match drop"
                type: str
            l3_entry_drop_max_hw_exceeded:
                description:
                - "L3 Entry Drop due to HW Limit Exceeded"
                type: str
            l4_entry_added:
                description:
                - "L4 Entry added"
                type: str
            l4_entry_deleted:
                description:
                - "L4 Entry deleted"
                type: str
            l4_entry_added_to_hw:
                description:
                - "L4 Entry added to HW"
                type: str
            l4_entry_removed_from_hw:
                description:
                - "L4 Entry removed from HW"
                type: str
            l4_hw_out_of_entries:
                description:
                - "HW out of L4 entries"
                type: str
            l4_entry_match_drop:
                description:
                - "L4 Entry match drop"
                type: str
            l4_entry_match_drop_hw:
                description:
                - "L4 HW Entry match drop"
                type: str
            l4_entry_drop_max_hw_exceeded:
                description:
                - "L4 Entry Drop due to HW Limit Exceeded"
                type: str
            l4_entry_list_alloc:
                description:
                - "L4 Entry list alloc"
                type: str
            l4_entry_list_free:
                description:
                - "L4 Entry list free"
                type: str
            l4_entry_list_alloc_failure:
                description:
                - "L4 Entry list alloc failures"
                type: str
            ip_node_alloc:
                description:
                - "Node alloc"
                type: str
            ip_node_free:
                description:
                - "Node free"
                type: str
            ip_node_alloc_failure:
                description:
                - "Node alloc failures"
                type: str
            ip_port_block_alloc:
                description:
                - "Port block alloc"
                type: str
            ip_port_block_free:
                description:
                - "Port block free"
                type: str
            ip_port_block_alloc_failure:
                description:
                - "Port block alloc failure"
                type: str
            ip_other_block_alloc:
                description:
                - "Other block alloc"
                type: str
            ip_other_block_free:
                description:
                - "Other block free"
                type: str
            ip_other_block_alloc_failure:
                description:
                - "Other block alloc failure"
                type: str
            entry_added_shadow:
                description:
                - "Entry added shadow"
                type: str
            entry_invalidated:
                description:
                - "Entry invalidated"
                type: str
            l3_entry_add_to_bgp_failure:
                description:
                - "L3 Entry BGP add failures"
                type: str
            l3_entry_remove_from_bgp_failure:
                description:
                - "L3 entry BGP remove failures"
                type: str
            l3_entry_add_to_hw_failure:
                description:
                - "L3 entry HW add failure"
                type: str
            syn_cookie_syn_ack_sent:
                description:
                - "SYN cookie SYN ACK sent"
                type: str
            syn_cookie_verification_passed:
                description:
                - "SYN cookie verification passed"
                type: str
            syn_cookie_verification_failed:
                description:
                - "SYN cookie verification failed"
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
AVAILABLE_PROPERTIES = ["disable_nat_ip_by_bgp", "enable_action", "ip_entries", "l4_entries", "logging_action", "max_hw_entries", "packets_per_second", "sampling_enable", "stats", "syn_cookie", "toggle", "uuid", "zone", ]


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
        'toggle': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'logging_action': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'enable_action': {
            'type': 'str',
            'choices': ['local', 'remote', 'both']
            },
        'packets_per_second': {
            'type': 'dict',
            'ip': {
                'type': 'int',
                },
            'action': {
                'type': 'dict',
                'action_type': {
                    'type': 'str',
                    'choices': ['log', 'drop', 'redistribute-route']
                    },
                'route_map': {
                    'type': 'str',
                    },
                'expiration': {
                    'type': 'int',
                    },
                'expiration_route': {
                    'type': 'int',
                    },
                'timer_multiply_max': {
                    'type': 'int',
                    },
                'remove_wait_timer': {
                    'type': 'int',
                    },
                'forward': {
                    'type': 'bool',
                    }
                },
            'tcp': {
                'type': 'int',
                },
            'tcp_action': {
                'type': 'dict',
                'tcp_action_type': {
                    'type': 'str',
                    'choices': ['log', 'drop']
                    },
                'tcp_expiration': {
                    'type': 'int',
                    }
                },
            'udp': {
                'type': 'int',
                },
            'udp_action': {
                'type': 'dict',
                'udp_action_type': {
                    'type': 'str',
                    'choices': ['log', 'drop']
                    },
                'udp_expiration': {
                    'type': 'int',
                    }
                },
            'other': {
                'type': 'int',
                },
            'other_action': {
                'type': 'dict',
                'other_action_type': {
                    'type': 'str',
                    'choices': ['log', 'drop']
                    },
                'other_expiration': {
                    'type': 'int',
                    }
                },
            'include_existing_session': {
                'type': 'bool',
                }
            },
        'syn_cookie': {
            'type': 'dict',
            'syn_cookie_enable': {
                'type': 'bool',
                },
            'syn_cookie_on_threshold': {
                'type': 'int',
                },
            'syn_cookie_on_timeout': {
                'type': 'int',
                }
            },
        'max_hw_entries': {
            'type': 'int',
            },
        'zone': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'l3_entry_added', 'l3_entry_deleted', 'l3_entry_added_to_bgp', 'l3_entry_removed_from_bgp', 'l3_entry_added_to_hw', 'l3_entry_removed_from_hw', 'l3_entry_too_many', 'l3_entry_match_drop', 'l3_entry_match_drop_hw', 'l3_entry_drop_max_hw_exceeded', 'l4_entry_added', 'l4_entry_deleted', 'l4_entry_added_to_hw',
                    'l4_entry_removed_from_hw', 'l4_hw_out_of_entries', 'l4_entry_match_drop', 'l4_entry_match_drop_hw', 'l4_entry_drop_max_hw_exceeded', 'l4_entry_list_alloc', 'l4_entry_list_free', 'l4_entry_list_alloc_failure', 'ip_node_alloc', 'ip_node_free', 'ip_node_alloc_failure', 'ip_port_block_alloc', 'ip_port_block_free',
                    'ip_port_block_alloc_failure', 'ip_other_block_alloc', 'ip_other_block_free', 'ip_other_block_alloc_failure', 'entry_added_shadow', 'entry_invalidated', 'l3_entry_add_to_bgp_failure', 'l3_entry_remove_from_bgp_failure', 'l3_entry_add_to_hw_failure', 'syn_cookie_syn_ack_sent', 'syn_cookie_verification_passed',
                    'syn_cookie_verification_failed', 'syn_cookie_conn_setup_failed'
                    ]
                }
            },
        'l4_entries': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ip_entries': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'disable_nat_ip_by_bgp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'l3_entry_added': {
                'type': 'str',
                },
            'l3_entry_deleted': {
                'type': 'str',
                },
            'l3_entry_added_to_bgp': {
                'type': 'str',
                },
            'l3_entry_removed_from_bgp': {
                'type': 'str',
                },
            'l3_entry_added_to_hw': {
                'type': 'str',
                },
            'l3_entry_removed_from_hw': {
                'type': 'str',
                },
            'l3_entry_too_many': {
                'type': 'str',
                },
            'l3_entry_match_drop': {
                'type': 'str',
                },
            'l3_entry_match_drop_hw': {
                'type': 'str',
                },
            'l3_entry_drop_max_hw_exceeded': {
                'type': 'str',
                },
            'l4_entry_added': {
                'type': 'str',
                },
            'l4_entry_deleted': {
                'type': 'str',
                },
            'l4_entry_added_to_hw': {
                'type': 'str',
                },
            'l4_entry_removed_from_hw': {
                'type': 'str',
                },
            'l4_hw_out_of_entries': {
                'type': 'str',
                },
            'l4_entry_match_drop': {
                'type': 'str',
                },
            'l4_entry_match_drop_hw': {
                'type': 'str',
                },
            'l4_entry_drop_max_hw_exceeded': {
                'type': 'str',
                },
            'l4_entry_list_alloc': {
                'type': 'str',
                },
            'l4_entry_list_free': {
                'type': 'str',
                },
            'l4_entry_list_alloc_failure': {
                'type': 'str',
                },
            'ip_node_alloc': {
                'type': 'str',
                },
            'ip_node_free': {
                'type': 'str',
                },
            'ip_node_alloc_failure': {
                'type': 'str',
                },
            'ip_port_block_alloc': {
                'type': 'str',
                },
            'ip_port_block_free': {
                'type': 'str',
                },
            'ip_port_block_alloc_failure': {
                'type': 'str',
                },
            'ip_other_block_alloc': {
                'type': 'str',
                },
            'ip_other_block_free': {
                'type': 'str',
                },
            'ip_other_block_alloc_failure': {
                'type': 'str',
                },
            'entry_added_shadow': {
                'type': 'str',
                },
            'entry_invalidated': {
                'type': 'str',
                },
            'l3_entry_add_to_bgp_failure': {
                'type': 'str',
                },
            'l3_entry_remove_from_bgp_failure': {
                'type': 'str',
                },
            'l3_entry_add_to_hw_failure': {
                'type': 'str',
                },
            'syn_cookie_syn_ack_sent': {
                'type': 'str',
                },
            'syn_cookie_verification_passed': {
                'type': 'str',
                },
            'syn_cookie_verification_failed': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/ddos-protection"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/ddos-protection"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ddos-protection"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ddos-protection"].get(k) != v:
            change_results["changed"] = True
            config_changes["ddos-protection"][k] = v

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
    payload = utils.build_json("ddos-protection", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["ddos-protection"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ddos-protection-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ddos-protection"]["stats"] if info != "NotFound" else info
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
