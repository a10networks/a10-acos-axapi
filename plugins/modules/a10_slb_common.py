#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_common
description:
    - SLB related commands
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
    extended_stats:
        description:
        - "Enable global slb extended statistics"
        type: bool
        required: False
    stats_data_disable:
        description:
        - "Disable global slb data statistics"
        type: bool
        required: False
    graceful_shutdown_enable:
        description:
        - "Enable graceful shutdown"
        type: bool
        required: False
    graceful_shutdown:
        description:
        - "1-65535, in unit of seconds"
        type: int
        required: False
    entity:
        description:
        - "'server'= Graceful shutdown server/port only; 'virtual-server'= Graceful
          shutdown virtual server/port only;"
        type: str
        required: False
    after_disable:
        description:
        - "Graceful shutdown after disable server/port and/or virtual server/port"
        type: bool
        required: False
    rate_limit_logging:
        description:
        - "Configure rate limit logging"
        type: bool
        required: False
    max_local_rate:
        description:
        - "Set maximum local rate"
        type: int
        required: False
    max_remote_rate:
        description:
        - "Set maximum remote rate"
        type: int
        required: False
    exclude_destination:
        description:
        - "'local'= Maximum local rate; 'remote'= Maximum remote rate;  (Maximum rates)"
        type: str
        required: False
    range:
        description:
        - "auto translate port range"
        type: int
        required: False
    range_start:
        description:
        - "port range start"
        type: int
        required: False
    range_end:
        description:
        - "port range end"
        type: int
        required: False
    dsr_health_check_enable:
        description:
        - "Enable dsr-health-check (direct server return health check)"
        type: bool
        required: False
    override_port:
        description:
        - "Enable override port in DSR health check mode"
        type: bool
        required: False
    reset_stale_session:
        description:
        - "Send reset if session in delete queue receives a SYN packet"
        type: bool
        required: False
    dns_cache_enable:
        description:
        - "Enable DNS cache"
        type: bool
        required: False
    response_type:
        description:
        - "'single-answer'= Only cache DNS response with single answer; 'round-robin'=
          Round robin;"
        type: str
        required: False
    ttl_threshold:
        description:
        - "Only cache DNS response with longer TTL"
        type: int
        required: False
    dns_cache_age:
        description:
        - "Set DNS cache entry age, default is 300 seconds (1-1000000 seconds, default is
          300 seconds)"
        type: int
        required: False
    compress_block_size:
        description:
        - "Set compression block size (Compression block size in bytes)"
        type: int
        required: False
    dns_cache_entry_size:
        description:
        - "Set DNS cache entry size, default is 256 bytes (1-4096 bytes, default is 256
          bytes)"
        type: int
        required: False
    dns_vip_stateless:
        description:
        - "Enable DNS VIP stateless mode"
        type: bool
        required: False
    honor_server_response_ttl:
        description:
        - "Honor the server reponse TTL"
        type: bool
        required: False
    buff_thresh:
        description:
        - "Set buffer threshold"
        type: bool
        required: False
    buff_thresh_hw_buff:
        description:
        - "Set hardware buffer threshold"
        type: int
        required: False
    buff_thresh_relieve_thresh:
        description:
        - "Relieve threshold"
        type: int
        required: False
    buff_thresh_sys_buff_low:
        description:
        - "Set low water mark of system buffer"
        type: int
        required: False
    buff_thresh_sys_buff_high:
        description:
        - "Set high water mark of system buffer"
        type: int
        required: False
    max_buff_queued_per_conn:
        description:
        - "Set per connection buffer threshold (Buffer value range 128-4096)"
        type: int
        required: False
    pkt_rate_for_reset_unknown_conn:
        description:
        - "Field pkt_rate_for_reset_unknown_conn"
        type: int
        required: False
    log_for_reset_unknown_conn:
        description:
        - "Log when rate exceed"
        type: bool
        required: False
    gateway_health_check:
        description:
        - "Enable gateway health check"
        type: bool
        required: False
    interval:
        description:
        - "Specify the healthcheck interval, default is 5 seconds (Interval Value, in
          seconds (default 5))"
        type: int
        required: False
    timeout:
        description:
        - "Specify the healthcheck timeout value, default is 15 seconds (Timeout Value, in
          seconds (default 15))"
        type: int
        required: False
    msl_time:
        description:
        - "Configure maximum session life, default is 2 seconds (1-40 seconds, default is
          2 seconds)"
        type: int
        required: False
    fast_path_disable:
        description:
        - "Disable fast path in SLB processing"
        type: bool
        required: False
    l2l3_trunk_lb_disable:
        description:
        - "Disable L2/L3 trunk LB"
        type: bool
        required: False
    snat_gwy_for_l3:
        description:
        - "Use source NAT gateway for L3 traffic for transparent mode"
        type: bool
        required: False
    allow_in_gateway_mode:
        description:
        - "Use source NAT gateway for L3 traffic for gateway mode"
        type: bool
        required: False
    disable_server_auto_reselect:
        description:
        - "Disable auto reselection of server"
        type: bool
        required: False
    enable_l7_req_acct:
        description:
        - "Enable L7 request accounting"
        type: bool
        required: False
    disable_adaptive_resource_check:
        description:
        - "Disable adaptive resource check based on buffer usage"
        type: bool
        required: False
    snat_on_vip:
        description:
        - "Enable source NAT traffic against VIP"
        type: bool
        required: False
    low_latency:
        description:
        - "Enable low latency mode"
        type: bool
        required: False
    mss_table:
        description:
        - "Set MSS table (128-750, default is 536)"
        type: int
        required: False
    resolve_port_conflict:
        description:
        - "Enable client port service port conflicts"
        type: bool
        required: False
    no_auto_up_on_aflex:
        description:
        - "Don't automatically mark vport up when aFleX is bound"
        type: bool
        required: False
    hw_compression:
        description:
        - "Use hardware compression"
        type: bool
        required: False
    hw_syn_rr:
        description:
        - "Configure hardware SYN round robin (range 1-500000)"
        type: int
        required: False
    max_http_header_count:
        description:
        - "Set maximum number of HTTP headers allowed"
        type: int
        required: False
    scale_out:
        description:
        - "Enable SLB scale out"
        type: bool
        required: False
    sort_res:
        description:
        - "Enable SLB sorting of resource names"
        type: bool
        required: False
    use_mss_tab:
        description:
        - "Use MSS based on internal table for SLB processing"
        type: bool
        required: False
    auto_nat_no_ip_refresh:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    ddos_protection:
        description:
        - "Field ddos_protection"
        type: dict
        required: False
        suboptions:
            ipd_enable_toggle:
                description:
                - "'enable'= Enable SLB DDoS protection; 'disable'= Disable SLB DDoS protection
          (default);"
                type: str
            logging:
                description:
                - "Field logging"
                type: dict
            packets_per_second:
                description:
                - "Field packets_per_second"
                type: dict
    ssli_sni_hash_enable:
        description:
        - "Enable SSLi SNI hash table"
        type: bool
        required: False
    software:
        description:
        - "Software"
        type: bool
        required: False
    ecmp_hash:
        description:
        - "'system-default'= Use system default ecmp hashing algorithm; 'connection-
          based'= Use connection information for hashing;"
        type: str
        required: False
    drop_icmp_to_vip_when_vip_down:
        description:
        - "Drop ICMP to VIP when VIP down"
        type: bool
        required: False
    player_id_check_enable:
        description:
        - "Enable the Player id check"
        type: bool
        required: False
    stateless_sg_multi_binding:
        description:
        - "Enable stateless service groups to be assigned to multiple L2/L3 DSR VIPs"
        type: bool
        required: False
    disable_persist_scoring:
        description:
        - "Disable Persist Scoring"
        type: bool
        required: False
    ipv4_offset:
        description:
        - "IPv4 Octet Offset for Hash"
        type: int
        required: False
    disable_port_masking:
        description:
        - "Disable masking of ports for CPU hashing"
        type: bool
        required: False
    snat_preserve:
        description:
        - "Field snat_preserve"
        type: dict
        required: False
        suboptions:
            range:
                description:
                - "Field range"
                type: list
    service_group_on_no_dest_nat_vports:
        description:
        - "'allow-same'= Allow the binding service-group on no-dest-nat virtual ports;
          'enforce-different'= Enforce that the same service-group can not be bound on
          different no-dest-nat virtual ports;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    conn_rate_limit:
        description:
        - "Field conn_rate_limit"
        type: dict
        required: False
        suboptions:
            src_ip_list:
                description:
                - "Field src_ip_list"
                type: list
    dns_response_rate_limiting:
        description:
        - "Field dns_response_rate_limiting"
        type: dict
        required: False
        suboptions:
            max_table_entries:
                description:
                - "Maximum number of entries allowed"
                type: int
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
            server_auto_reselect:
                description:
                - "Field server_auto_reselect"
                type: int

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
    "after_disable",
    "allow_in_gateway_mode",
    "auto_nat_no_ip_refresh",
    "buff_thresh",
    "buff_thresh_hw_buff",
    "buff_thresh_relieve_thresh",
    "buff_thresh_sys_buff_high",
    "buff_thresh_sys_buff_low",
    "compress_block_size",
    "conn_rate_limit",
    "ddos_protection",
    "disable_adaptive_resource_check",
    "disable_persist_scoring",
    "disable_port_masking",
    "disable_server_auto_reselect",
    "dns_cache_age",
    "dns_cache_enable",
    "dns_cache_entry_size",
    "dns_response_rate_limiting",
    "dns_vip_stateless",
    "drop_icmp_to_vip_when_vip_down",
    "dsr_health_check_enable",
    "ecmp_hash",
    "enable_l7_req_acct",
    "entity",
    "exclude_destination",
    "extended_stats",
    "fast_path_disable",
    "gateway_health_check",
    "graceful_shutdown",
    "graceful_shutdown_enable",
    "honor_server_response_ttl",
    "hw_compression",
    "hw_syn_rr",
    "interval",
    "ipv4_offset",
    "l2l3_trunk_lb_disable",
    "log_for_reset_unknown_conn",
    "low_latency",
    "max_buff_queued_per_conn",
    "max_http_header_count",
    "max_local_rate",
    "max_remote_rate",
    "msl_time",
    "mss_table",
    "no_auto_up_on_aflex",
    "oper",
    "override_port",
    "pkt_rate_for_reset_unknown_conn",
    "player_id_check_enable",
    "range",
    "range_end",
    "range_start",
    "rate_limit_logging",
    "reset_stale_session",
    "resolve_port_conflict",
    "response_type",
    "scale_out",
    "service_group_on_no_dest_nat_vports",
    "snat_gwy_for_l3",
    "snat_on_vip",
    "snat_preserve",
    "software",
    "sort_res",
    "ssli_sni_hash_enable",
    "stateless_sg_multi_binding",
    "stats_data_disable",
    "timeout",
    "ttl_threshold",
    "use_mss_tab",
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
        'extended_stats': {
            'type': 'bool',
        },
        'stats_data_disable': {
            'type': 'bool',
        },
        'graceful_shutdown_enable': {
            'type': 'bool',
        },
        'graceful_shutdown': {
            'type': 'int',
        },
        'entity': {
            'type': 'str',
            'choices': ['server', 'virtual-server']
        },
        'after_disable': {
            'type': 'bool',
        },
        'rate_limit_logging': {
            'type': 'bool',
        },
        'max_local_rate': {
            'type': 'int',
        },
        'max_remote_rate': {
            'type': 'int',
        },
        'exclude_destination': {
            'type': 'str',
            'choices': ['local', 'remote']
        },
        'range': {
            'type': 'int',
        },
        'range_start': {
            'type': 'int',
        },
        'range_end': {
            'type': 'int',
        },
        'dsr_health_check_enable': {
            'type': 'bool',
        },
        'override_port': {
            'type': 'bool',
        },
        'reset_stale_session': {
            'type': 'bool',
        },
        'dns_cache_enable': {
            'type': 'bool',
        },
        'response_type': {
            'type': 'str',
            'choices': ['single-answer', 'round-robin']
        },
        'ttl_threshold': {
            'type': 'int',
        },
        'dns_cache_age': {
            'type': 'int',
        },
        'compress_block_size': {
            'type': 'int',
        },
        'dns_cache_entry_size': {
            'type': 'int',
        },
        'dns_vip_stateless': {
            'type': 'bool',
        },
        'honor_server_response_ttl': {
            'type': 'bool',
        },
        'buff_thresh': {
            'type': 'bool',
        },
        'buff_thresh_hw_buff': {
            'type': 'int',
        },
        'buff_thresh_relieve_thresh': {
            'type': 'int',
        },
        'buff_thresh_sys_buff_low': {
            'type': 'int',
        },
        'buff_thresh_sys_buff_high': {
            'type': 'int',
        },
        'max_buff_queued_per_conn': {
            'type': 'int',
        },
        'pkt_rate_for_reset_unknown_conn': {
            'type': 'int',
        },
        'log_for_reset_unknown_conn': {
            'type': 'bool',
        },
        'gateway_health_check': {
            'type': 'bool',
        },
        'interval': {
            'type': 'int',
        },
        'timeout': {
            'type': 'int',
        },
        'msl_time': {
            'type': 'int',
        },
        'fast_path_disable': {
            'type': 'bool',
        },
        'l2l3_trunk_lb_disable': {
            'type': 'bool',
        },
        'snat_gwy_for_l3': {
            'type': 'bool',
        },
        'allow_in_gateway_mode': {
            'type': 'bool',
        },
        'disable_server_auto_reselect': {
            'type': 'bool',
        },
        'enable_l7_req_acct': {
            'type': 'bool',
        },
        'disable_adaptive_resource_check': {
            'type': 'bool',
        },
        'snat_on_vip': {
            'type': 'bool',
        },
        'low_latency': {
            'type': 'bool',
        },
        'mss_table': {
            'type': 'int',
        },
        'resolve_port_conflict': {
            'type': 'bool',
        },
        'no_auto_up_on_aflex': {
            'type': 'bool',
        },
        'hw_compression': {
            'type': 'bool',
        },
        'hw_syn_rr': {
            'type': 'int',
        },
        'max_http_header_count': {
            'type': 'int',
        },
        'scale_out': {
            'type': 'bool',
        },
        'sort_res': {
            'type': 'bool',
        },
        'use_mss_tab': {
            'type': 'bool',
        },
        'auto_nat_no_ip_refresh': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'ddos_protection': {
            'type': 'dict',
            'ipd_enable_toggle': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'logging': {
                'type': 'dict',
                'ipd_logging_toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                }
            },
            'packets_per_second': {
                'type': 'dict',
                'ipd_tcp': {
                    'type': 'int',
                },
                'ipd_udp': {
                    'type': 'int',
                }
            }
        },
        'ssli_sni_hash_enable': {
            'type': 'bool',
        },
        'software': {
            'type': 'bool',
        },
        'ecmp_hash': {
            'type': 'str',
            'choices': ['system-default', 'connection-based']
        },
        'drop_icmp_to_vip_when_vip_down': {
            'type': 'bool',
        },
        'player_id_check_enable': {
            'type': 'bool',
        },
        'stateless_sg_multi_binding': {
            'type': 'bool',
        },
        'disable_persist_scoring': {
            'type': 'bool',
        },
        'ipv4_offset': {
            'type': 'int',
        },
        'disable_port_masking': {
            'type': 'bool',
        },
        'snat_preserve': {
            'type': 'dict',
            'range': {
                'type': 'list',
                'port1': {
                    'type': 'int',
                },
                'port2': {
                    'type': 'int',
                }
            }
        },
        'service_group_on_no_dest_nat_vports': {
            'type': 'str',
            'choices': ['allow-same', 'enforce-different']
        },
        'uuid': {
            'type': 'str',
        },
        'conn_rate_limit': {
            'type': 'dict',
            'src_ip_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                },
                'limit': {
                    'type': 'int',
                },
                'limit_period': {
                    'type': 'str',
                    'choices': ['100', '1000']
                },
                'shared': {
                    'type': 'bool',
                },
                'exceed_action': {
                    'type': 'bool',
                },
                'log': {
                    'type': 'bool',
                },
                'lock_out': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'dns_response_rate_limiting': {
            'type': 'dict',
            'max_table_entries': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'server_auto_reselect': {
                'type': 'int',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/common"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/slb/common"

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
        for k, v in payload["common"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["common"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["common"][k] = v
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
    payload = build_json("common", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
