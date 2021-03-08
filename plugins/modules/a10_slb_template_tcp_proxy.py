#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_tcp_proxy
description:
    - TCP Proxy
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
        - "TCP Proxy Template Name"
        type: str
        required: True
    ack_aggressiveness:
        description:
        - "'low'= Delayed ACK; 'medium'= Delayed ACK, with ACK on each packet with PUSH
          flag; 'high'= ACK on each packet;"
        type: str
        required: False
    backend_wscale:
        description:
        - "The TCP window scale used for the server side, default is off (number)"
        type: int
        required: False
    dynamic_buffer_allocation:
        description:
        - "Optimally adjust the transmit and receive buffer sizes of TCP proxy while
          keeping their sum constant"
        type: bool
        required: False
    fin_timeout:
        description:
        - "FIN timeout (sec), default is disabled (number)"
        type: int
        required: False
    force_delete_timeout:
        description:
        - "The maximum time that a session can stay in the system before being deleted,
          default is off (number (second))"
        type: int
        required: False
    force_delete_timeout_100ms:
        description:
        - "The maximum time that a session can stay in the system before being deleted,
          default is off (number in 100ms)"
        type: int
        required: False
    alive_if_active:
        description:
        - "keep connection alive if active traffic"
        type: bool
        required: False
    idle_timeout:
        description:
        - "Idle Timeout (Interval of 60 seconds), default is 600 (idle timeout in second,
          default 600)"
        type: int
        required: False
    server_down_action:
        description:
        - "'FIN'= FIN Connection; 'RST'= Reset Connection;"
        type: str
        required: False
    half_open_idle_timeout:
        description:
        - "TCP Half Open Idle Timeout (sec), default is off (number)"
        type: int
        required: False
    half_close_idle_timeout:
        description:
        - "TCP Half Close Idle Timeout (sec), default is off (cmd is deprecated, use fin-
          timeout instead) (number)"
        type: int
        required: False
    init_cwnd:
        description:
        - "The initial congestion control window size (packets), default is 10 (init-cwnd
          in packets, default 10)"
        type: int
        required: False
    initial_window_size:
        description:
        - "Set the initial window size, default is off (number)"
        type: int
        required: False
    keepalive_interval:
        description:
        - "Interval between keepalive probes (sec), default is off (number (seconds))"
        type: int
        required: False
    keepalive_probes:
        description:
        - "Number of keepalive probes sent, default is off"
        type: int
        required: False
    mss:
        description:
        - "Responding MSS to use if client MSS is large, default is off (number)"
        type: int
        required: False
    psh_flag_optimization:
        description:
        - "Enable Optimized PSH Flag Use"
        type: bool
        required: False
    nagle:
        description:
        - "Enable Nagle Algorithm"
        type: bool
        required: False
    qos:
        description:
        - "QOS level (number)"
        type: int
        required: False
    receive_buffer:
        description:
        - "TCP Receive Buffer (default 200k) (number default 200000 bytes)"
        type: int
        required: False
    reno:
        description:
        - "Enable Reno Congestion Control Algorithm"
        type: bool
        required: False
    transmit_buffer:
        description:
        - "TCP Transmit Buffer (default 200k) (number default 200000 bytes)"
        type: int
        required: False
    reset_fwd:
        description:
        - "send reset to server if error happens"
        type: bool
        required: False
    reset_rev:
        description:
        - "send reset to client if error happens"
        type: bool
        required: False
    disable:
        description:
        - "send reset to client when server is disabled"
        type: bool
        required: False
    down:
        description:
        - "send reset to client when server is down"
        type: bool
        required: False
    del_session_on_server_down:
        description:
        - "Delete session if the server/port goes down (either disabled/hm down)"
        type: bool
        required: False
    retransmit_retries:
        description:
        - "Number of Retries for Retransmit, default is 5"
        type: int
        required: False
    insert_client_ip:
        description:
        - "Insert client ip into TCP option"
        type: bool
        required: False
    syn_retries:
        description:
        - "SYN Retry Numbers, default is 5"
        type: int
        required: False
    timewait:
        description:
        - "Timewait Threshold (sec), default 5 (number)"
        type: int
        required: False
    disable_tcp_timestamps:
        description:
        - "disable TCP Timestamps Option"
        type: bool
        required: False
    disable_window_scale:
        description:
        - "disable TCP Window-Scale Option"
        type: bool
        required: False
    disable_sack:
        description:
        - "disable Selective Ack Option"
        type: bool
        required: False
    invalid_rate_limit:
        description:
        - "Invalid Packet Response Rate Limit (ms), default is 500 (number default 500
          challenges)"
        type: int
        required: False
    disable_abc:
        description:
        - "Appropriate Byte Counting RFC 3465 Disabled, default is enabled (Appropriate
          Byte Counting (ABC) is enabled by default)"
        type: bool
        required: False
    reassembly_timeout:
        description:
        - "The reassembly timeout, default is 30sec (number)"
        type: int
        required: False
    reassembly_limit:
        description:
        - "The reassembly queuing limit, default is 25 segments (number)"
        type: int
        required: False
    min_rto:
        description:
        - "The minmum retransmission timeout, default is 200ms (number)"
        type: int
        required: False
    limited_slowstart:
        description:
        - "RFC 3742 Limited Slow-Start for TCP with Large Congestion Windows (number)"
        type: int
        required: False
    early_retransmit:
        description:
        - "Configure the Early-Retransmit Algorithm (RFC 5827) (Early-Retransmit is
          disabled by default)"
        type: bool
        required: False
    maxburst:
        description:
        - "The max packet count sent per transmission event (number)"
        type: int
        required: False
    proxy_header:
        description:
        - "Field proxy_header"
        type: dict
        required: False
        suboptions:
            proxy_header_action:
                description:
                - "'insert'= Insert proxy header;"
                type: str
            version:
                description:
                - "'v1'= version 1; 'v2'= version 2;"
                type: str
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
    "ack_aggressiveness",
    "alive_if_active",
    "backend_wscale",
    "del_session_on_server_down",
    "disable",
    "disable_abc",
    "disable_sack",
    "disable_tcp_timestamps",
    "disable_window_scale",
    "down",
    "dynamic_buffer_allocation",
    "early_retransmit",
    "fin_timeout",
    "force_delete_timeout",
    "force_delete_timeout_100ms",
    "half_close_idle_timeout",
    "half_open_idle_timeout",
    "idle_timeout",
    "init_cwnd",
    "initial_window_size",
    "insert_client_ip",
    "invalid_rate_limit",
    "keepalive_interval",
    "keepalive_probes",
    "limited_slowstart",
    "maxburst",
    "min_rto",
    "mss",
    "nagle",
    "name",
    "proxy_header",
    "psh_flag_optimization",
    "qos",
    "reassembly_limit",
    "reassembly_timeout",
    "receive_buffer",
    "reno",
    "reset_fwd",
    "reset_rev",
    "retransmit_retries",
    "server_down_action",
    "syn_retries",
    "timewait",
    "transmit_buffer",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'ack_aggressiveness': {
            'type': 'str',
            'choices': ['low', 'medium', 'high']
        },
        'backend_wscale': {
            'type': 'int',
        },
        'dynamic_buffer_allocation': {
            'type': 'bool',
        },
        'fin_timeout': {
            'type': 'int',
        },
        'force_delete_timeout': {
            'type': 'int',
        },
        'force_delete_timeout_100ms': {
            'type': 'int',
        },
        'alive_if_active': {
            'type': 'bool',
        },
        'idle_timeout': {
            'type': 'int',
        },
        'server_down_action': {
            'type': 'str',
            'choices': ['FIN', 'RST']
        },
        'half_open_idle_timeout': {
            'type': 'int',
        },
        'half_close_idle_timeout': {
            'type': 'int',
        },
        'init_cwnd': {
            'type': 'int',
        },
        'initial_window_size': {
            'type': 'int',
        },
        'keepalive_interval': {
            'type': 'int',
        },
        'keepalive_probes': {
            'type': 'int',
        },
        'mss': {
            'type': 'int',
        },
        'psh_flag_optimization': {
            'type': 'bool',
        },
        'nagle': {
            'type': 'bool',
        },
        'qos': {
            'type': 'int',
        },
        'receive_buffer': {
            'type': 'int',
        },
        'reno': {
            'type': 'bool',
        },
        'transmit_buffer': {
            'type': 'int',
        },
        'reset_fwd': {
            'type': 'bool',
        },
        'reset_rev': {
            'type': 'bool',
        },
        'disable': {
            'type': 'bool',
        },
        'down': {
            'type': 'bool',
        },
        'del_session_on_server_down': {
            'type': 'bool',
        },
        'retransmit_retries': {
            'type': 'int',
        },
        'insert_client_ip': {
            'type': 'bool',
        },
        'syn_retries': {
            'type': 'int',
        },
        'timewait': {
            'type': 'int',
        },
        'disable_tcp_timestamps': {
            'type': 'bool',
        },
        'disable_window_scale': {
            'type': 'bool',
        },
        'disable_sack': {
            'type': 'bool',
        },
        'invalid_rate_limit': {
            'type': 'int',
        },
        'disable_abc': {
            'type': 'bool',
        },
        'reassembly_timeout': {
            'type': 'int',
        },
        'reassembly_limit': {
            'type': 'int',
        },
        'min_rto': {
            'type': 'int',
        },
        'limited_slowstart': {
            'type': 'int',
        },
        'early_retransmit': {
            'type': 'bool',
        },
        'maxburst': {
            'type': 'int',
        },
        'proxy_header': {
            'type': 'dict',
            'proxy_header_action': {
                'type': 'str',
                'choices': ['insert']
            },
            'version': {
                'type': 'str',
                'choices': ['v1', 'v2']
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["tcp-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["tcp-proxy"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["tcp-proxy"][k] = v
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
    payload = build_json("tcp-proxy", module)
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
