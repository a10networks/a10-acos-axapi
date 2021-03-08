#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ipv6_in_ipv4_frag
description:
    - IPv6-in-IPv4 fragmentation parameters
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
                - "'all'= all; 'session-inserted'= Session Inserted; 'session-expired'= Session
          Expired; 'icmp-rcv'= ICMP Received; 'icmpv6-rcv'= ICMPv6 Received; 'udp-rcv'=
          UDP Received; 'tcp-rcv'= TCP Received; 'ipip-rcv'= IP-in-IP Received; 'ipv6ip-
          rcv'= IPv6-in-IP Received; 'other-rcv'= Other Received; 'icmp-dropped'= ICMP
          Dropped; 'icmpv6-dropped'= ICMPv6 Dropped; 'udp-dropped'= UDP Dropped; 'tcp-
          dropped'= TCP Dropped; 'ipip-dropped'= IP-in-IP Dropped; 'ipv6ip-dropped'=
          IPv6-in-IP Dropped; 'other-dropped'= Other Dropped; 'overlap-error'=
          Overlapping Fragment Dropped; 'bad-ip-len'= Bad IP Length; 'too-small'=
          Fragment Too Small Drop; 'first-tcp-too-small'= First TCP Fragment Too Small
          Drop; 'first-l4-too-small'= First L4 Fragment Too Small Drop; 'total-sessions-
          exceeded'= Total Sessions Exceeded Drop; 'no-session-memory'= Out of Session
          Memory; 'fast-aging-set'= Fragmentation Fast Aging Set; 'fast-aging-unset'=
          Fragmentation Fast Aging Unset; 'fragment-queue-success'= Fragment Queue
          Success; 'unaligned-len'= Payload Length Unaligned; 'exceeded-len'= Payload
          Length Out of Bounds; 'duplicate-first-frag'= Duplicate First Fragment;
          'duplicate-last-frag'= Duplicate Last Fragment; 'total-fragments-exceeded'=
          Total Queued Fragments Exceeded; 'fragment-queue-failure'= Fragment Queue
          Failure; 'reassembly-success'= Fragment Reassembly Success; 'max-len-exceeded'=
          Fragment Max Data Length Exceeded; 'reassembly-failure'= Fragment Reassembly
          Failure; 'policy-drop'= MTU Exceeded Policy Drop; 'error-drop'= Fragment
          Processing Drop; 'high-cpu-threshold'= High CPU Threshold Reached; 'low-cpu-
          threshold'= Low CPU Threshold Reached; 'cpu-threshold-drop'= High CPU Drop;
          'ipd-entry-drop'= DDoS Protection Drop; 'max-packets-exceeded'= Too Many
          Packets Per Reassembly Drop; 'session-packets-exceeded'= Session Max Packets
          Exceeded; 'frag-session-count'= Fragmentation Session Count; 'sctp-rcv'= SCTP
          Received; 'sctp-dropped'= SCTP Dropped;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            session_inserted:
                description:
                - "Session Inserted"
                type: str
            session_expired:
                description:
                - "Session Expired"
                type: str
            icmp_rcv:
                description:
                - "ICMP Received"
                type: str
            icmpv6_rcv:
                description:
                - "ICMPv6 Received"
                type: str
            udp_rcv:
                description:
                - "UDP Received"
                type: str
            tcp_rcv:
                description:
                - "TCP Received"
                type: str
            ipip_rcv:
                description:
                - "IP-in-IP Received"
                type: str
            ipv6ip_rcv:
                description:
                - "IPv6-in-IP Received"
                type: str
            other_rcv:
                description:
                - "Other Received"
                type: str
            icmp_dropped:
                description:
                - "ICMP Dropped"
                type: str
            icmpv6_dropped:
                description:
                - "ICMPv6 Dropped"
                type: str
            udp_dropped:
                description:
                - "UDP Dropped"
                type: str
            tcp_dropped:
                description:
                - "TCP Dropped"
                type: str
            ipip_dropped:
                description:
                - "IP-in-IP Dropped"
                type: str
            ipv6ip_dropped:
                description:
                - "IPv6-in-IP Dropped"
                type: str
            other_dropped:
                description:
                - "Other Dropped"
                type: str
            overlap_error:
                description:
                - "Overlapping Fragment Dropped"
                type: str
            bad_ip_len:
                description:
                - "Bad IP Length"
                type: str
            too_small:
                description:
                - "Fragment Too Small Drop"
                type: str
            first_tcp_too_small:
                description:
                - "First TCP Fragment Too Small Drop"
                type: str
            first_l4_too_small:
                description:
                - "First L4 Fragment Too Small Drop"
                type: str
            total_sessions_exceeded:
                description:
                - "Total Sessions Exceeded Drop"
                type: str
            no_session_memory:
                description:
                - "Out of Session Memory"
                type: str
            fast_aging_set:
                description:
                - "Fragmentation Fast Aging Set"
                type: str
            fast_aging_unset:
                description:
                - "Fragmentation Fast Aging Unset"
                type: str
            fragment_queue_success:
                description:
                - "Fragment Queue Success"
                type: str
            unaligned_len:
                description:
                - "Payload Length Unaligned"
                type: str
            exceeded_len:
                description:
                - "Payload Length Out of Bounds"
                type: str
            duplicate_first_frag:
                description:
                - "Duplicate First Fragment"
                type: str
            duplicate_last_frag:
                description:
                - "Duplicate Last Fragment"
                type: str
            total_fragments_exceeded:
                description:
                - "Total Queued Fragments Exceeded"
                type: str
            fragment_queue_failure:
                description:
                - "Fragment Queue Failure"
                type: str
            reassembly_success:
                description:
                - "Fragment Reassembly Success"
                type: str
            max_len_exceeded:
                description:
                - "Fragment Max Data Length Exceeded"
                type: str
            reassembly_failure:
                description:
                - "Fragment Reassembly Failure"
                type: str
            policy_drop:
                description:
                - "MTU Exceeded Policy Drop"
                type: str
            error_drop:
                description:
                - "Fragment Processing Drop"
                type: str
            high_cpu_threshold:
                description:
                - "High CPU Threshold Reached"
                type: str
            low_cpu_threshold:
                description:
                - "Low CPU Threshold Reached"
                type: str
            cpu_threshold_drop:
                description:
                - "High CPU Drop"
                type: str
            ipd_entry_drop:
                description:
                - "DDoS Protection Drop"
                type: str
            max_packets_exceeded:
                description:
                - "Too Many Packets Per Reassembly Drop"
                type: str
            session_packets_exceeded:
                description:
                - "Session Max Packets Exceeded"
                type: str
            sctp_rcv:
                description:
                - "SCTP Received"
                type: str
            sctp_dropped:
                description:
                - "SCTP Dropped"
                type: str

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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'session-inserted', 'session-expired', 'icmp-rcv',
                    'icmpv6-rcv', 'udp-rcv', 'tcp-rcv', 'ipip-rcv',
                    'ipv6ip-rcv', 'other-rcv', 'icmp-dropped',
                    'icmpv6-dropped', 'udp-dropped', 'tcp-dropped',
                    'ipip-dropped', 'ipv6ip-dropped', 'other-dropped',
                    'overlap-error', 'bad-ip-len', 'too-small',
                    'first-tcp-too-small', 'first-l4-too-small',
                    'total-sessions-exceeded', 'no-session-memory',
                    'fast-aging-set', 'fast-aging-unset',
                    'fragment-queue-success', 'unaligned-len', 'exceeded-len',
                    'duplicate-first-frag', 'duplicate-last-frag',
                    'total-fragments-exceeded', 'fragment-queue-failure',
                    'reassembly-success', 'max-len-exceeded',
                    'reassembly-failure', 'policy-drop', 'error-drop',
                    'high-cpu-threshold', 'low-cpu-threshold',
                    'cpu-threshold-drop', 'ipd-entry-drop',
                    'max-packets-exceeded', 'session-packets-exceeded',
                    'frag-session-count', 'sctp-rcv', 'sctp-dropped'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'session_inserted': {
                'type': 'str',
            },
            'session_expired': {
                'type': 'str',
            },
            'icmp_rcv': {
                'type': 'str',
            },
            'icmpv6_rcv': {
                'type': 'str',
            },
            'udp_rcv': {
                'type': 'str',
            },
            'tcp_rcv': {
                'type': 'str',
            },
            'ipip_rcv': {
                'type': 'str',
            },
            'ipv6ip_rcv': {
                'type': 'str',
            },
            'other_rcv': {
                'type': 'str',
            },
            'icmp_dropped': {
                'type': 'str',
            },
            'icmpv6_dropped': {
                'type': 'str',
            },
            'udp_dropped': {
                'type': 'str',
            },
            'tcp_dropped': {
                'type': 'str',
            },
            'ipip_dropped': {
                'type': 'str',
            },
            'ipv6ip_dropped': {
                'type': 'str',
            },
            'other_dropped': {
                'type': 'str',
            },
            'overlap_error': {
                'type': 'str',
            },
            'bad_ip_len': {
                'type': 'str',
            },
            'too_small': {
                'type': 'str',
            },
            'first_tcp_too_small': {
                'type': 'str',
            },
            'first_l4_too_small': {
                'type': 'str',
            },
            'total_sessions_exceeded': {
                'type': 'str',
            },
            'no_session_memory': {
                'type': 'str',
            },
            'fast_aging_set': {
                'type': 'str',
            },
            'fast_aging_unset': {
                'type': 'str',
            },
            'fragment_queue_success': {
                'type': 'str',
            },
            'unaligned_len': {
                'type': 'str',
            },
            'exceeded_len': {
                'type': 'str',
            },
            'duplicate_first_frag': {
                'type': 'str',
            },
            'duplicate_last_frag': {
                'type': 'str',
            },
            'total_fragments_exceeded': {
                'type': 'str',
            },
            'fragment_queue_failure': {
                'type': 'str',
            },
            'reassembly_success': {
                'type': 'str',
            },
            'max_len_exceeded': {
                'type': 'str',
            },
            'reassembly_failure': {
                'type': 'str',
            },
            'policy_drop': {
                'type': 'str',
            },
            'error_drop': {
                'type': 'str',
            },
            'high_cpu_threshold': {
                'type': 'str',
            },
            'low_cpu_threshold': {
                'type': 'str',
            },
            'cpu_threshold_drop': {
                'type': 'str',
            },
            'ipd_entry_drop': {
                'type': 'str',
            },
            'max_packets_exceeded': {
                'type': 'str',
            },
            'session_packets_exceeded': {
                'type': 'str',
            },
            'sctp_rcv': {
                'type': 'str',
            },
            'sctp_dropped': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ipv6-in-ipv4/frag"

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
    url_base = "/axapi/v3/ipv6-in-ipv4/frag"

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
        for k, v in payload["frag"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["frag"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["frag"][k] = v
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
    payload = build_json("frag", module)
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
