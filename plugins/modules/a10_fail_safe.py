#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fail_safe
description:
    - Fail Safe Global Commands
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
    fpga_buff_recovery_threshold:
        description:
        - "FPGA buffers recovery threshold (Units of 256 buffers (default 2))"
        type: int
        required: False
    fpga_monitor_enable:
        description:
        - "FPGA monitor feature enable"
        type: bool
        required: False
    fpga_monitor_forced_reboot:
        description:
        - "FPGA monitor forced reboot in error condition"
        type: bool
        required: False
    fpga_monitor_interval:
        description:
        - "FPGA monitor packet interval (seconds) (Numbers of seconds between sending
          packets (default 1))"
        type: int
        required: False
    fpga_monitor_threshold:
        description:
        - "FPGA monitor packet missed for error condition (Numbers of missed monitor
          packets before setting error condition (default 3))"
        type: int
        required: False
    hw_error_monitor:
        description:
        - "'hw-error-monitor-disable'= Disable fail-safe hardware error monitor; 'hw-
          error-monitor-enable'= Enable fail-safe hardware error monitor;"
        type: str
        required: False
    hw_ssl_timeout_monitor:
        description:
        - "'hw-ssl-timeout-monitor-disable'= Disable fail-safe hardware SSL timeout
          monitor; 'hw-ssl-timeout-monitor-enable'= Enable fail-safe hardware SSL timeout
          monitor;"
        type: str
        required: False
    hw_error_recovery_timeout:
        description:
        - "Hardware error recovery timeout (minutes) (waiting time of recovery from
          hardware errors (default 0))"
        type: int
        required: False
    session_mem_recovery_threshold:
        description:
        - "Session memory recovery threshold (percentage) (Percentage of available session
          memory (default 30%))"
        type: int
        required: False
    sw_error_monitor_enable:
        description:
        - "Enable fail-safe software error monitor"
        type: bool
        required: False
    sw_error_recovery_timeout:
        description:
        - "Software error recovery timeout (minutes) (waiting time of recovery from
          software errors (default 3))"
        type: int
        required: False
    total_memory_size_check:
        description:
        - "Check total memory size of current system (Size of memory (GB))"
        type: int
        required: False
    log:
        description:
        - "Log the event"
        type: bool
        required: False
    kill:
        description:
        - "Stop the traffic and log the event"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    config:
        description:
        - "Field config"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    disable_failsafe:
        description:
        - "Field disable_failsafe"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "'all'= Disable All; 'io-buffer'= Disable I/O Buffer; 'session-memory'= Disable
          Session Memory; 'system-memory'= Disable System Memory;"
                type: str
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
            free_session_memory:
                description:
                - "Field free_session_memory"
                type: int
            total_session_memory:
                description:
                - "Field total_session_memory"
                type: int
            sess_mem_recovery_threshold:
                description:
                - "Field sess_mem_recovery_threshold"
                type: int
            total_fpga_buffers:
                description:
                - "Field total_fpga_buffers"
                type: int
            avail_fpga_buff_domain1:
                description:
                - "Field avail_fpga_buff_domain1"
                type: int
            avail_fpga_buff_domain2:
                description:
                - "Field avail_fpga_buff_domain2"
                type: int
            total_free_fpga_buff:
                description:
                - "Field total_free_fpga_buff"
                type: int
            free_fpga_buffers:
                description:
                - "Field free_fpga_buffers"
                type: int
            fpga_buff_recovery_threshold:
                description:
                - "Field fpga_buff_recovery_threshold"
                type: int
            total_system_memory:
                description:
                - "Field total_system_memory"
                type: int
            fpga_stats_num_cntrs:
                description:
                - "Field fpga_stats_num_cntrs"
                type: int
            fpga_stats_iochan:
                description:
                - "Field fpga_stats_iochan"
                type: list
            config:
                description:
                - "Field config"
                type: dict

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
    "config",
    "disable_failsafe",
    "fpga_buff_recovery_threshold",
    "fpga_monitor_enable",
    "fpga_monitor_forced_reboot",
    "fpga_monitor_interval",
    "fpga_monitor_threshold",
    "hw_error_monitor",
    "hw_error_recovery_timeout",
    "hw_ssl_timeout_monitor",
    "kill",
    "log",
    "oper",
    "session_mem_recovery_threshold",
    "sw_error_monitor_enable",
    "sw_error_recovery_timeout",
    "total_memory_size_check",
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
        'fpga_buff_recovery_threshold': {
            'type': 'int',
        },
        'fpga_monitor_enable': {
            'type': 'bool',
        },
        'fpga_monitor_forced_reboot': {
            'type': 'bool',
        },
        'fpga_monitor_interval': {
            'type': 'int',
        },
        'fpga_monitor_threshold': {
            'type': 'int',
        },
        'hw_error_monitor': {
            'type': 'str',
            'choices': ['hw-error-monitor-disable', 'hw-error-monitor-enable']
        },
        'hw_ssl_timeout_monitor': {
            'type':
            'str',
            'choices': [
                'hw-ssl-timeout-monitor-disable',
                'hw-ssl-timeout-monitor-enable'
            ]
        },
        'hw_error_recovery_timeout': {
            'type': 'int',
        },
        'session_mem_recovery_threshold': {
            'type': 'int',
        },
        'sw_error_monitor_enable': {
            'type': 'bool',
        },
        'sw_error_recovery_timeout': {
            'type': 'int',
        },
        'total_memory_size_check': {
            'type': 'int',
        },
        'log': {
            'type': 'bool',
        },
        'kill': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'config': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'disable_failsafe': {
            'type': 'dict',
            'action': {
                'type': 'str',
                'choices':
                ['all', 'io-buffer', 'session-memory', 'system-memory']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'free_session_memory': {
                'type': 'int',
            },
            'total_session_memory': {
                'type': 'int',
            },
            'sess_mem_recovery_threshold': {
                'type': 'int',
            },
            'total_fpga_buffers': {
                'type': 'int',
            },
            'avail_fpga_buff_domain1': {
                'type': 'int',
            },
            'avail_fpga_buff_domain2': {
                'type': 'int',
            },
            'total_free_fpga_buff': {
                'type': 'int',
            },
            'free_fpga_buffers': {
                'type': 'int',
            },
            'fpga_buff_recovery_threshold': {
                'type': 'int',
            },
            'total_system_memory': {
                'type': 'int',
            },
            'fpga_stats_num_cntrs': {
                'type': 'int',
            },
            'fpga_stats_iochan': {
                'type': 'list',
                'fpga_stats_iochan_id': {
                    'type': 'int',
                },
                'fpga_stats_iochan_tx': {
                    'type': 'int',
                },
                'fpga_stats_iochan_rx': {
                    'type': 'int',
                }
            },
            'config': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'sw_error_mon': {
                        'type': 'str',
                    },
                    'hw_error_mon': {
                        'type': 'str',
                    },
                    'sw_recovery_timeout': {
                        'type': 'str',
                    },
                    'hw_recovery_timeout': {
                        'type': 'str',
                    },
                    'fpga_mon_enable': {
                        'type': 'str',
                    },
                    'fpga_mon_forced_reboot': {
                        'type': 'str',
                    },
                    'fpga_mon_interval': {
                        'type': 'str',
                    },
                    'fpga_mon_threshold': {
                        'type': 'str',
                    },
                    'mem_mon': {
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
    url_base = "/axapi/v3/fail-safe"

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
    url_base = "/axapi/v3/fail-safe"

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
        for k, v in payload["fail-safe"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["fail-safe"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["fail-safe"][k] = v
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
    payload = build_json("fail-safe", module)
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
