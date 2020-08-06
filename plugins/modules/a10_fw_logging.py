#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_logging
description:
    - Bind a logging template to firewall
short_description: Configures A10 fw.logging
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
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
          Fragmentation Failed; 'ipv6-frag-applied'= IPv6 Fragmentation Applied; 'ipv6
          -frag-failed'= IPv6 Fragmentation Failed; 'out-of-buffers'= Out of Buffers;
          'add-msg-failed'= Add Message to Buffer Failed; 'tcp-logging-conn-established'=
          TCP Logging Conn Established; 'tcp-logging-conn-create-failed'= TCP Logging
          Conn Create Failed; 'tcp-logging-conn-dropped'= TCP Logging Conn Dropped; 'log-
          message-too-long'= Log message too long; 'http-out-of-order-dropped'= HTTP out-
          of-order dropped; 'http-alloc-failed'= HTTP Request Info Allocation Failed;
          'sctp-session-created'= SCTP Session Created; 'sctp-session-deleted'= SCTP
          Session Deleted; 'log_type_sctp_inner_proto_filter'= Log Event Type SCTP Inner
          Proto Filter; 'log_type_gtp_message_filtering'= Log Event Type GTP Message
          Filtering; 'log_type_gtp_apn_filtering'= Log Event Type GTP Apn Filtering;
          'tcp-logging-port-allocated'= TCP Logging Port Allocated; 'tcp-logging-port-
          freed'= TCP Logging Port Freed; 'tcp-logging-port-allocation-failed'= TCP
          Logging Port Allocation Failed; 'log_type_gtp_invalid_teid'= Log Event Type GTP
          Invalid TEID; 'log_gtp_type_reserved_ie_present'= Log Event Type GTP Reserved
          Information Element Present; 'log_type_gtp_mandatory_ie_missing'= Log Event
          Type GTP Mandatory Information Element Missing;"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            tcp_session_deleted:
                description:
                - "TCP Session Deleted"
            log_type_gtp_mandatory_ie_missing:
                description:
                - "Log Event Type GTP Mandatory Information Element Missing"
            icmpv6_session_created:
                description:
                - "ICMPV6 Session Created"
            log_type_gtp_apn_filtering:
                description:
                - "Log Event Type GTP Apn Filtering"
            tcp_session_created:
                description:
                - "TCP Session Created"
            sctp_session_created:
                description:
                - "SCTP Session Created"
            udp_session_created:
                description:
                - "UDP Session Created"
            http_request_logged:
                description:
                - "HTTP Request Logged"
            other_session_created:
                description:
                - "Other Session Created"
            log_type_gtp_invalid_teid:
                description:
                - "Log Event Type GTP Invalid TEID"
            rule_not_logged:
                description:
                - "Firewall Rule Not Logged"
            other_session_deleted:
                description:
                - "Other Session Deleted"
            http_logging_invalid_format:
                description:
                - "HTTP Logging Invalid Format Error"
            log_gtp_type_reserved_ie_present:
                description:
                - "Log Event Type GTP Reserved Information Element Present"
            sctp_session_deleted:
                description:
                - "SCTP Session Deleted"
            icmpv6_session_deleted:
                description:
                - "ICMPV6 Session Deleted"
            log_type_deny:
                description:
                - "Log Event Type Deny"
            log_type_gtp_message_filtering:
                description:
                - "Log Event Type GTP Message Filtering"
            log_type_reset:
                description:
                - "Log Event Type Reset"
            log_type_session_opened:
                description:
                - "Log Event Type Session Open"
            log_type_session_closed:
                description:
                - "Log Event Type Session Close"
            log_type_sctp_inner_proto_filter:
                description:
                - "Log Event Type SCTP Inner Proto Filter"
            icmp_session_deleted:
                description:
                - "ICMP Session Deleted"
            icmp_session_created:
                description:
                - "ICMP Session Created"
            log_message_sent:
                description:
                - "Log Packet Sent"
            log_dropped:
                description:
                - "Log Packets Dropped"
            udp_session_deleted:
                description:
                - "UDP Session Deleted"
    name:
        description:
        - "Logging Template Name"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "name",
    "sampling_enable",
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'log_message_sent', 'log_type_reset',
                    'log_type_deny', 'log_type_session_closed',
                    'log_type_session_opened', 'rule_not_logged',
                    'log-dropped', 'tcp-session-created',
                    'tcp-session-deleted', 'udp-session-created',
                    'udp-session-deleted', 'icmp-session-deleted',
                    'icmp-session-created', 'icmpv6-session-deleted',
                    'icmpv6-session-created', 'other-session-deleted',
                    'other-session-created', 'http-request-logged',
                    'http-logging-invalid-format', 'dcmsg_permit',
                    'alg_override_permit', 'template_error',
                    'ipv4-frag-applied', 'ipv4-frag-failed',
                    'ipv6-frag-applied', 'ipv6-frag-failed', 'out-of-buffers',
                    'add-msg-failed', 'tcp-logging-conn-established',
                    'tcp-logging-conn-create-failed',
                    'tcp-logging-conn-dropped', 'log-message-too-long',
                    'http-out-of-order-dropped', 'http-alloc-failed',
                    'sctp-session-created', 'sctp-session-deleted',
                    'log_type_sctp_inner_proto_filter',
                    'log_type_gtp_message_filtering',
                    'log_type_gtp_apn_filtering', 'tcp-logging-port-allocated',
                    'tcp-logging-port-freed',
                    'tcp-logging-port-allocation-failed',
                    'log_type_gtp_invalid_teid',
                    'log_gtp_type_reserved_ie_present',
                    'log_type_gtp_mandatory_ie_missing'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'tcp_session_deleted': {
                'type': 'str',
            },
            'log_type_gtp_mandatory_ie_missing': {
                'type': 'str',
            },
            'icmpv6_session_created': {
                'type': 'str',
            },
            'log_type_gtp_apn_filtering': {
                'type': 'str',
            },
            'tcp_session_created': {
                'type': 'str',
            },
            'sctp_session_created': {
                'type': 'str',
            },
            'udp_session_created': {
                'type': 'str',
            },
            'http_request_logged': {
                'type': 'str',
            },
            'other_session_created': {
                'type': 'str',
            },
            'log_type_gtp_invalid_teid': {
                'type': 'str',
            },
            'rule_not_logged': {
                'type': 'str',
            },
            'other_session_deleted': {
                'type': 'str',
            },
            'http_logging_invalid_format': {
                'type': 'str',
            },
            'log_gtp_type_reserved_ie_present': {
                'type': 'str',
            },
            'sctp_session_deleted': {
                'type': 'str',
            },
            'icmpv6_session_deleted': {
                'type': 'str',
            },
            'log_type_deny': {
                'type': 'str',
            },
            'log_type_gtp_message_filtering': {
                'type': 'str',
            },
            'log_type_reset': {
                'type': 'str',
            },
            'log_type_session_opened': {
                'type': 'str',
            },
            'log_type_session_closed': {
                'type': 'str',
            },
            'log_type_sctp_inner_proto_filter': {
                'type': 'str',
            },
            'icmp_session_deleted': {
                'type': 'str',
            },
            'icmp_session_created': {
                'type': 'str',
            },
            'log_message_sent': {
                'type': 'str',
            },
            'log_dropped': {
                'type': 'str',
            },
            'udp_session_deleted': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["logging"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["logging"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["logging"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("logging", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
