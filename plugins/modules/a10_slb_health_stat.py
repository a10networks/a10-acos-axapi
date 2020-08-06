#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_health_stat
description:
    - Configure health monitor
short_description: Configures A10 slb.health-stat
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
            health_check_list:
                description:
                - "Field health_check_list"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'num_burst'= Number of burst; 'max_jiffie'= Maximum number of
          jiffies; 'min_jiffie'= Minimum number of jiffies; 'avg_jiffie'= Average number
          of jiffies; 'open_socket'= Number of open sockets; 'open_socket_failed'= Number
          of failed open sockets; 'close_socket'= Number of closed sockets;
          'connect_failed'= Number of failed connections; 'send_packet'= Number of
          packets sent; 'send_packet_failed'= Number of packet send failures;
          'recv_packet'= Number of received packets; 'recv_packet_failed'= Number of
          failed packet receives; 'retry_times'= Retry times; 'timeout'= Timouet value;
          'unexpected_error'= Number of unexpected errors; 'conn_imdt_succ'= Number of
          connection immediete success; 'sock_close_before_17'= Number of sockets closed
          before l7; 'sock_close_without_notify'= Number of sockets closed without
          notify; 'curr_health_rate'= Current health rate; 'ext_health_rate'= External
          health rate; 'ext_health_rate_val'= External health rate value; 'total_number'=
          Total number; 'status_up'= Number of status ups; 'status_down'= Number of
          status downs; 'status_unkn'= Number of status unknowns; 'status_other'= Number
          of other status; 'running_time'= Running time; 'config_health_rate'= Config
          health rate;"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            min_jiffie:
                description:
                - "Minimum number of jiffies"
            unexpected_error:
                description:
                - "Number of unexpected errors"
            avg_jiffie:
                description:
                - "Average number of jiffies"
            num_burst:
                description:
                - "Number of burst"
            status_unkn:
                description:
                - "Number of status unknowns"
            retry_times:
                description:
                - "Retry times"
            send_packet:
                description:
                - "Number of packets sent"
            status_other:
                description:
                - "Number of other status"
            curr_health_rate:
                description:
                - "Current health rate"
            config_health_rate:
                description:
                - "Config health rate"
            status_down:
                description:
                - "Number of status downs"
            recv_packet_failed:
                description:
                - "Number of failed packet receives"
            close_socket:
                description:
                - "Number of closed sockets"
            conn_imdt_succ:
                description:
                - "Number of connection immediete success"
            recv_packet:
                description:
                - "Number of received packets"
            send_packet_failed:
                description:
                - "Number of packet send failures"
            open_socket_failed:
                description:
                - "Number of failed open sockets"
            sock_close_before_17:
                description:
                - "Number of sockets closed before l7"
            total_number:
                description:
                - "Total number"
            ext_health_rate_val:
                description:
                - "External health rate value"
            open_socket:
                description:
                - "Number of open sockets"
            sock_close_without_notify:
                description:
                - "Number of sockets closed without notify"
            status_up:
                description:
                - "Number of status ups"
            running_time:
                description:
                - "Running time"
            connect_failed:
                description:
                - "Number of failed connections"
            max_jiffie:
                description:
                - "Maximum number of jiffies"
            ext_health_rate:
                description:
                - "External health rate"
            timeout:
                description:
                - "Timouet value"
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
    "oper",
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
        'oper': {
            'type': 'dict',
            'health_check_list': {
                'type': 'list',
                'status': {
                    'type': 'str',
                },
                'retries': {
                    'type': 'int',
                },
                'down_state': {
                    'type': 'int',
                },
                'down_cause': {
                    'type': 'int',
                },
                'up_retries': {
                    'type': 'int',
                },
                'server': {
                    'type': 'str',
                },
                'partition_id': {
                    'type': 'int',
                },
                'up_cause': {
                    'type': 'int',
                },
                'reason': {
                    'type': 'str',
                },
                'ip_address': {
                    'type': 'str',
                },
                'total_retry': {
                    'type': 'int',
                },
                'health_monitor': {
                    'type': 'str',
                },
                'port': {
                    'type': 'str',
                }
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'num_burst', 'max_jiffie', 'min_jiffie',
                    'avg_jiffie', 'open_socket', 'open_socket_failed',
                    'close_socket', 'connect_failed', 'send_packet',
                    'send_packet_failed', 'recv_packet', 'recv_packet_failed',
                    'retry_times', 'timeout', 'unexpected_error',
                    'conn_imdt_succ', 'sock_close_before_17',
                    'sock_close_without_notify', 'curr_health_rate',
                    'ext_health_rate', 'ext_health_rate_val', 'total_number',
                    'status_up', 'status_down', 'status_unkn', 'status_other',
                    'running_time', 'config_health_rate'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'min_jiffie': {
                'type': 'str',
            },
            'unexpected_error': {
                'type': 'str',
            },
            'avg_jiffie': {
                'type': 'str',
            },
            'num_burst': {
                'type': 'str',
            },
            'status_unkn': {
                'type': 'str',
            },
            'retry_times': {
                'type': 'str',
            },
            'send_packet': {
                'type': 'str',
            },
            'status_other': {
                'type': 'str',
            },
            'curr_health_rate': {
                'type': 'str',
            },
            'config_health_rate': {
                'type': 'str',
            },
            'status_down': {
                'type': 'str',
            },
            'recv_packet_failed': {
                'type': 'str',
            },
            'close_socket': {
                'type': 'str',
            },
            'conn_imdt_succ': {
                'type': 'str',
            },
            'recv_packet': {
                'type': 'str',
            },
            'send_packet_failed': {
                'type': 'str',
            },
            'open_socket_failed': {
                'type': 'str',
            },
            'sock_close_before_17': {
                'type': 'str',
            },
            'total_number': {
                'type': 'str',
            },
            'ext_health_rate_val': {
                'type': 'str',
            },
            'open_socket': {
                'type': 'str',
            },
            'sock_close_without_notify': {
                'type': 'str',
            },
            'status_up': {
                'type': 'str',
            },
            'running_time': {
                'type': 'str',
            },
            'connect_failed': {
                'type': 'str',
            },
            'max_jiffie': {
                'type': 'str',
            },
            'ext_health_rate': {
                'type': 'str',
            },
            'timeout': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/health-stat"

    f_dict = {}

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
    url_base = "/axapi/v3/slb/health-stat"

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
        for k, v in payload["health-stat"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["health-stat"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["health-stat"][k] = v
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
    payload = build_json("health-stat", module)
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
