#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_nat_pool
description:
    - Configure CGNv6 NAT pool
short_description: Configures A10 cgnv6.nat.pool
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            nat_ip_list:
                description:
                - "Field nat_ip_list"
            pool_name:
                description:
                - "Specify pool name or pool group"
    all:
        description:
        - "Share with all partitions"
        required: False
    tcp_time_wait_interval:
        description:
        - "Minutes before TCP NAT ports can be reused"
        required: False
    group:
        description:
        - "Share with a partition group (Partition Group Name)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    start_address:
        description:
        - "Configure start IP address of NAT pool"
        required: False
    per_batch_port_usage_warning_threshold:
        description:
        - "Configure warning log threshold for per batch port usage (default= disabled)
          (Number of ports)"
        required: False
    vrid:
        description:
        - "Configure VRRP-A vrid (Specify ha VRRP-A vrid)"
        required: False
    usable_nat_ports_start:
        description:
        - "Start Port of Usable NAT Ports (needs to be even)"
        required: False
    usable_nat_ports_end:
        description:
        - "End Port of Usable NAT Ports"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            udp_hit_full:
                description:
                - "UDP Hit Full"
            ip_free:
                description:
                - "IP Free"
            ip_used:
                description:
                - "IP Used"
            tcp:
                description:
                - "TCP"
            udp_rsvd:
                description:
                - "UDP Reserved"
            icmp_freed:
                description:
                - "ICMP Freed"
            icmp_hit_full:
                description:
                - "ICMP Hit Full"
            icmp_total:
                description:
                - "ICMP Total"
            tcp_peak:
                description:
                - "TCP Peak"
            icmp_rsvd:
                description:
                - "ICMP Reserved"
            udp_freed:
                description:
                - "UDP Freed"
            pool_name:
                description:
                - "Specify pool name or pool group"
            tcp_freed:
                description:
                - "TCP Freed"
            udp:
                description:
                - "UDP"
            users:
                description:
                - "Users"
            tcp_hit_full:
                description:
                - "TCP Hit Full"
            tcp_rsvd:
                description:
                - "TCP Reserved"
            icmp:
                description:
                - "ICMP"
            udp_peak:
                description:
                - "UDP Peak"
            udp_total:
                description:
                - "UDP Total"
            icmp_peak:
                description:
                - "ICMP Peak"
            ip_total:
                description:
                - "IP Total"
            tcp_total:
                description:
                - "TCP total"
    partition:
        description:
        - "Share with a single partition (Partition Name)"
        required: False
    netmask:
        description:
        - "Configure mask for pool"
        required: False
    max_users_per_ip:
        description:
        - "Number of users that can be assigned to a NAT IP"
        required: False
    simultaneous_batch_allocation:
        description:
        - "Allocate same TCP and UDP batches at once"
        required: False
    shared:
        description:
        - "Share this pool with other partitions (default= not shared)"
        required: False
    port_batch_v2_size:
        description:
        - "'64'= Allocate 64 ports at a time; '128'= Allocate 128 ports at a time; '256'=
          Allocate 256 ports at a time; '512'= Allocate 512 ports at a time; '1024'=
          Allocate 1024 ports at a time; '2048'= Allocate 2048 ports at a time; '4096'=
          Allocate 4096 ports at a time;"
        required: False
    end_address:
        description:
        - "Configure end IP address of NAT pool"
        required: False
    usable_nat_ports:
        description:
        - "Configure usable NAT ports"
        required: False
    exclude_ip:
        description:
        - "Field exclude_ip"
        required: False
        suboptions:
            exclude_ip_start:
                description:
                - "Single IP address or IP address range start"
            exclude_ip_end:
                description:
                - "Address range end"
    pool_name:
        description:
        - "Specify pool name or pool group"
        required: True


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
    "all",
    "end_address",
    "exclude_ip",
    "group",
    "max_users_per_ip",
    "netmask",
    "oper",
    "partition",
    "per_batch_port_usage_warning_threshold",
    "pool_name",
    "port_batch_v2_size",
    "shared",
    "simultaneous_batch_allocation",
    "start_address",
    "stats",
    "tcp_time_wait_interval",
    "usable_nat_ports",
    "usable_nat_ports_end",
    "usable_nat_ports_start",
    "uuid",
    "vrid",
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
        'oper': {
            'type': 'dict',
            'nat_ip_list': {
                'type': 'list',
                'udp_used': {
                    'type': 'int',
                },
                'udp_hit_full': {
                    'type': 'int',
                },
                'rtsp_used': {
                    'type': 'int',
                },
                'ip_address': {
                    'type': 'str',
                },
                'icmp_freed': {
                    'type': 'int',
                },
                'icmp_hit_full': {
                    'type': 'int',
                },
                'icmp_total': {
                    'type': 'int',
                },
                'tcp_peak': {
                    'type': 'int',
                },
                'icmp_reserved': {
                    'type': 'int',
                },
                'udp_freed': {
                    'type': 'int',
                },
                'udp_reserved': {
                    'type': 'int',
                },
                'tcp_freed': {
                    'type': 'int',
                },
                'users': {
                    'type': 'int',
                },
                'tcp_hit_full': {
                    'type': 'int',
                },
                'obsoleted': {
                    'type': 'int',
                },
                'udp_peak': {
                    'type': 'int',
                },
                'udp_total': {
                    'type': 'int',
                },
                'icmp_peak': {
                    'type': 'int',
                },
                'tcp_reserved': {
                    'type': 'int',
                },
                'tcp_used': {
                    'type': 'int',
                },
                'tcp_total': {
                    'type': 'int',
                },
                'icmp_used': {
                    'type': 'int',
                }
            },
            'pool_name': {
                'type': 'str',
                'required': True,
            }
        },
        'all': {
            'type': 'bool',
        },
        'tcp_time_wait_interval': {
            'type': 'int',
        },
        'group': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'start_address': {
            'type': 'str',
        },
        'per_batch_port_usage_warning_threshold': {
            'type': 'int',
        },
        'vrid': {
            'type': 'int',
        },
        'usable_nat_ports_start': {
            'type': 'int',
        },
        'usable_nat_ports_end': {
            'type': 'int',
        },
        'stats': {
            'type': 'dict',
            'udp_hit_full': {
                'type': 'str',
            },
            'ip_free': {
                'type': 'str',
            },
            'ip_used': {
                'type': 'str',
            },
            'tcp': {
                'type': 'str',
            },
            'udp_rsvd': {
                'type': 'str',
            },
            'icmp_freed': {
                'type': 'str',
            },
            'icmp_hit_full': {
                'type': 'str',
            },
            'icmp_total': {
                'type': 'str',
            },
            'tcp_peak': {
                'type': 'str',
            },
            'icmp_rsvd': {
                'type': 'str',
            },
            'udp_freed': {
                'type': 'str',
            },
            'pool_name': {
                'type': 'str',
                'required': True,
            },
            'tcp_freed': {
                'type': 'str',
            },
            'udp': {
                'type': 'str',
            },
            'users': {
                'type': 'str',
            },
            'tcp_hit_full': {
                'type': 'str',
            },
            'tcp_rsvd': {
                'type': 'str',
            },
            'icmp': {
                'type': 'str',
            },
            'udp_peak': {
                'type': 'str',
            },
            'udp_total': {
                'type': 'str',
            },
            'icmp_peak': {
                'type': 'str',
            },
            'ip_total': {
                'type': 'str',
            },
            'tcp_total': {
                'type': 'str',
            }
        },
        'partition': {
            'type': 'str',
        },
        'netmask': {
            'type': 'str',
        },
        'max_users_per_ip': {
            'type': 'int',
        },
        'simultaneous_batch_allocation': {
            'type': 'bool',
        },
        'shared': {
            'type': 'bool',
        },
        'port_batch_v2_size': {
            'type': 'str',
            'choices': ['64', '128', '256', '512', '1024', '2048', '4096']
        },
        'end_address': {
            'type': 'str',
        },
        'usable_nat_ports': {
            'type': 'bool',
        },
        'exclude_ip': {
            'type': 'list',
            'exclude_ip_start': {
                'type': 'str',
            },
            'exclude_ip_end': {
                'type': 'str',
            }
        },
        'pool_name': {
            'type': 'str',
            'required': True,
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/nat/pool/{pool-name}"

    f_dict = {}
    f_dict["pool-name"] = module.params["pool_name"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


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


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/cgnv6/nat/pool/{pool-name}"

    f_dict = {}
    f_dict["pool-name"] = ""

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
        for k, v in payload["pool"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["pool"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["pool"][k] = v
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
    payload = build_json("pool", module)
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
