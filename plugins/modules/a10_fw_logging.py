#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_logging
description:
    - logging configurations e.g. FW logging template Binding/CEF log options
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
        - "Logging Template Name"
        type: str
        required: False
    cef_label:
        description:
        - "'enable'= enable; 'disable'= disable;"
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
                - "'all'= all; 'log_message_sent'= Log Packet Sent; 'log_type_reset'= Log Event
          Type Reset; 'log_type_deny'= Log Event Type Deny; 'log_type_session_closed'=
          Log Event Type Session Close; 'log_type_session_opened'= Log Event Type Session
          Open; 'rule_not_logged'= Firewall Rule Not Logged; 'log-dropped'= Log Packets
          Dropped; 'tcp-session-created'= TCP Session Created; 'tcp-session-deleted'= TCP
          Session Deleted; 'udp-session-created'= UDP Session Created; 'udp-session-
          deleted'= UDP Session Deleted; 'icmp-session-deleted'= ICMP Session Deleted;
          'icmp-session-created'= ICMP Session Created; 'icmpv6-session-deleted'= ICMPV6
          Session Deleted; 'icmpv6-session-created'= ICMPV6 Session Created; 'other-
          session-deleted'= Other Session Deleted; 'other-session-created'= Other Session
          Created; 'http-request-logged'= HTTP Request Logged; 'http-logging-invalid-
          format'= HTTP Logging Invalid Format Error; 'dcmsg_permit'= Dcmsg Permit;
          'alg_override_permit'= Alg Override Permit; 'template_error'= Template Error;
          'ipv4-frag-applied'= IPv4 Fragmentation Applied; 'ipv4-frag-failed'= IPv4
          Fragmentation Failed; 'ipv6-frag-applied'= IPv6 Fragmentation Applied;
          'ipv6-frag-failed'= IPv6 Fragmentation Failed; 'out-of-buffers'= Out of
          Buffers; 'add-msg-failed'= Add Message to Buffer Failed; 'tcp-logging-conn-
          established'= TCP Logging Conn Established; 'tcp-logging-conn-create-failed'=
          TCP Logging Conn Create Failed; 'tcp-logging-conn-dropped'= TCP Logging Conn
          Dropped; 'log-message-too-long'= Log message too long; 'http-out-of-order-
          dropped'= HTTP out-of-order dropped; 'http-alloc-failed'= HTTP Request Info
          Allocation Failed; 'sctp-session-created'= SCTP Session Created; 'sctp-session-
          deleted'= SCTP Session Deleted; 'log_type_sctp_inner_proto_filter'= Log Event
          Type SCTP Inner Proto Filter; 'tcp-logging-port-allocated'= TCP Logging Port
          Allocated; 'tcp-logging-port-freed'= TCP Logging Port Freed; 'tcp-logging-port-
          allocation-failed'= TCP Logging Port Allocation Failed; 'iddos-blackhole-entry-
          create'= iDDoS IP Entry Created; 'iddos-blackhole-entry-delete'= iDDoS IP Entry
          Deleted; 'session-limit-exceeded'= Session Limit Exceeded;"
                type: str
    gtp:
        description:
        - "Field gtp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            log_message_sent:
                description:
                - "Log Packet Sent"
                type: str
            log_type_reset:
                description:
                - "Log Event Type Reset"
                type: str
            log_type_deny:
                description:
                - "Log Event Type Deny"
                type: str
            log_type_session_closed:
                description:
                - "Log Event Type Session Close"
                type: str
            log_type_session_opened:
                description:
                - "Log Event Type Session Open"
                type: str
            rule_not_logged:
                description:
                - "Firewall Rule Not Logged"
                type: str
            log_dropped:
                description:
                - "Log Packets Dropped"
                type: str
            tcp_session_created:
                description:
                - "TCP Session Created"
                type: str
            tcp_session_deleted:
                description:
                - "TCP Session Deleted"
                type: str
            udp_session_created:
                description:
                - "UDP Session Created"
                type: str
            udp_session_deleted:
                description:
                - "UDP Session Deleted"
                type: str
            icmp_session_deleted:
                description:
                - "ICMP Session Deleted"
                type: str
            icmp_session_created:
                description:
                - "ICMP Session Created"
                type: str
            icmpv6_session_deleted:
                description:
                - "ICMPV6 Session Deleted"
                type: str
            icmpv6_session_created:
                description:
                - "ICMPV6 Session Created"
                type: str
            other_session_deleted:
                description:
                - "Other Session Deleted"
                type: str
            other_session_created:
                description:
                - "Other Session Created"
                type: str
            http_request_logged:
                description:
                - "HTTP Request Logged"
                type: str
            http_logging_invalid_format:
                description:
                - "HTTP Logging Invalid Format Error"
                type: str
            sctp_session_created:
                description:
                - "SCTP Session Created"
                type: str
            sctp_session_deleted:
                description:
                - "SCTP Session Deleted"
                type: str
            log_type_sctp_inner_proto_filter:
                description:
                - "Log Event Type SCTP Inner Proto Filter"
                type: str
            iddos_blackhole_entry_create:
                description:
                - "iDDoS IP Entry Created"
                type: str
            iddos_blackhole_entry_delete:
                description:
                - "iDDoS IP Entry Deleted"
                type: str
            session_limit_exceeded:
                description:
                - "Session Limit Exceeded"
                type: str
            gtp:
                description:
                - "Field gtp"
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
AVAILABLE_PROPERTIES = ["cef_label", "gtp", "name", "sampling_enable", "stats", "uuid", ]


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
            },
        'cef_label': {
            'type': 'str',
            'choices': ['enable', 'disable']
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
                    'all', 'log_message_sent', 'log_type_reset', 'log_type_deny', 'log_type_session_closed', 'log_type_session_opened', 'rule_not_logged', 'log-dropped', 'tcp-session-created', 'tcp-session-deleted', 'udp-session-created', 'udp-session-deleted', 'icmp-session-deleted', 'icmp-session-created', 'icmpv6-session-deleted',
                    'icmpv6-session-created', 'other-session-deleted', 'other-session-created', 'http-request-logged', 'http-logging-invalid-format', 'dcmsg_permit', 'alg_override_permit', 'template_error', 'ipv4-frag-applied', 'ipv4-frag-failed', 'ipv6-frag-applied', 'ipv6-frag-failed', 'out-of-buffers', 'add-msg-failed',
                    'tcp-logging-conn-established', 'tcp-logging-conn-create-failed', 'tcp-logging-conn-dropped', 'log-message-too-long', 'http-out-of-order-dropped', 'http-alloc-failed', 'sctp-session-created', 'sctp-session-deleted', 'log_type_sctp_inner_proto_filter', 'tcp-logging-port-allocated', 'tcp-logging-port-freed',
                    'tcp-logging-port-allocation-failed', 'iddos-blackhole-entry-create', 'iddos-blackhole-entry-delete', 'session-limit-exceeded'
                    ]
                }
            },
        'gtp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'log_type_gtp_invalid_teid', 'log_gtp_type_reserved_ie_present', 'log_type_gtp_mandatory_ie_missing', 'log_type_gtp_mandatory_ie_inside_grouped_ie_missing', 'log_type_gtp_msisdn_filtering', 'log_type_gtp_out_of_order_ie', 'log_type_gtp_out_of_state_ie', 'log_type_enduser_ip_spoofed', 'log_type_crosslayer_correlation',
                        'log_type_message_not_supported', 'log_type_out_of_state', 'log_type_max_msg_length', 'log_type_gtp_message_filtering', 'log_type_gtp_apn_filtering', 'log_type_gtp_rat_type_filtering', 'log_type_country_code_mismatch', 'log_type_gtp_in_gtp_filtering', 'log_type_gtp_node_restart', 'log_type_gtp_seq_num_mismatch',
                        'log_type_gtp_rate_limit_periodic', 'log_type_gtp_invalid_message_length', 'log_type_gtp_hdr_invalid_protocol_flag', 'log_type_gtp_hdr_invalid_spare_bits', 'log_type_gtp_hdr_invalid_piggy_flag', 'log_type_gtp_invalid_version', 'log_type_gtp_invalid_ports'
                        ]
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'log_message_sent': {
                'type': 'str',
                },
            'log_type_reset': {
                'type': 'str',
                },
            'log_type_deny': {
                'type': 'str',
                },
            'log_type_session_closed': {
                'type': 'str',
                },
            'log_type_session_opened': {
                'type': 'str',
                },
            'rule_not_logged': {
                'type': 'str',
                },
            'log_dropped': {
                'type': 'str',
                },
            'tcp_session_created': {
                'type': 'str',
                },
            'tcp_session_deleted': {
                'type': 'str',
                },
            'udp_session_created': {
                'type': 'str',
                },
            'udp_session_deleted': {
                'type': 'str',
                },
            'icmp_session_deleted': {
                'type': 'str',
                },
            'icmp_session_created': {
                'type': 'str',
                },
            'icmpv6_session_deleted': {
                'type': 'str',
                },
            'icmpv6_session_created': {
                'type': 'str',
                },
            'other_session_deleted': {
                'type': 'str',
                },
            'other_session_created': {
                'type': 'str',
                },
            'http_request_logged': {
                'type': 'str',
                },
            'http_logging_invalid_format': {
                'type': 'str',
                },
            'sctp_session_created': {
                'type': 'str',
                },
            'sctp_session_deleted': {
                'type': 'str',
                },
            'log_type_sctp_inner_proto_filter': {
                'type': 'str',
                },
            'iddos_blackhole_entry_create': {
                'type': 'str',
                },
            'iddos_blackhole_entry_delete': {
                'type': 'str',
                },
            'session_limit_exceeded': {
                'type': 'str',
                },
            'gtp': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'log_type_gtp_invalid_teid': {
                        'type': 'str',
                        },
                    'log_gtp_type_reserved_ie_present': {
                        'type': 'str',
                        },
                    'log_type_gtp_mandatory_ie_missing': {
                        'type': 'str',
                        },
                    'log_type_gtp_mandatory_ie_inside_grouped_ie_missing': {
                        'type': 'str',
                        },
                    'log_type_gtp_msisdn_filtering': {
                        'type': 'str',
                        },
                    'log_type_gtp_out_of_order_ie': {
                        'type': 'str',
                        },
                    'log_type_gtp_out_of_state_ie': {
                        'type': 'str',
                        },
                    'log_type_enduser_ip_spoofed': {
                        'type': 'str',
                        },
                    'log_type_crosslayer_correlation': {
                        'type': 'str',
                        },
                    'log_type_message_not_supported': {
                        'type': 'str',
                        },
                    'log_type_out_of_state': {
                        'type': 'str',
                        },
                    'log_type_max_msg_length': {
                        'type': 'str',
                        },
                    'log_type_gtp_message_filtering': {
                        'type': 'str',
                        },
                    'log_type_gtp_apn_filtering': {
                        'type': 'str',
                        },
                    'log_type_gtp_rat_type_filtering': {
                        'type': 'str',
                        },
                    'log_type_country_code_mismatch': {
                        'type': 'str',
                        },
                    'log_type_gtp_in_gtp_filtering': {
                        'type': 'str',
                        },
                    'log_type_gtp_node_restart': {
                        'type': 'str',
                        },
                    'log_type_gtp_seq_num_mismatch': {
                        'type': 'str',
                        },
                    'log_type_gtp_rate_limit_periodic': {
                        'type': 'str',
                        },
                    'log_type_gtp_invalid_message_length': {
                        'type': 'str',
                        },
                    'log_type_gtp_hdr_invalid_protocol_flag': {
                        'type': 'str',
                        },
                    'log_type_gtp_hdr_invalid_spare_bits': {
                        'type': 'str',
                        },
                    'log_type_gtp_hdr_invalid_piggy_flag': {
                        'type': 'str',
                        },
                    'log_type_gtp_invalid_version': {
                        'type': 'str',
                        },
                    'log_type_gtp_invalid_ports': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["logging"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["logging"].get(k) != v:
            change_results["changed"] = True
            config_changes["logging"][k] = v

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
    payload = utils.build_json("logging", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["logging"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["logging-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["logging"]["stats"] if info != "NotFound" else info
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
