#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_service_group
description:
    - Service Group
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
        - "FW Service Name"
        type: str
        required: True
    protocol:
        description:
        - "'tcp'= TCP LB service; 'udp'= UDP LB service;"
        type: str
        required: False
    health_check:
        description:
        - "Health Check (Monitor Name)"
        type: str
        required: False
    traffic_replication_mirror_ip_repl:
        description:
        - "Replaces IP with server-IP"
        type: bool
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'server_selection_fail_drop'= Service selection fail drop;
          'server_selection_fail_reset'= Service selection fail reset;
          'service_peak_conn'= Service peak connection;"
                type: str
    member_list:
        description:
        - "Field member_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "Field state"
                type: str
            servers_up:
                description:
                - "Field servers_up"
                type: int
            servers_down:
                description:
                - "Field servers_down"
                type: int
            servers_disable:
                description:
                - "Field servers_disable"
                type: int
            servers_total:
                description:
                - "Field servers_total"
                type: int
            stateless_current_rate:
                description:
                - "Field stateless_current_rate"
                type: int
            stateless_current_usage:
                description:
                - "Field stateless_current_usage"
                type: int
            stateless_state:
                description:
                - "Field stateless_state"
                type: int
            stateless_type:
                description:
                - "Field stateless_type"
                type: int
            hm_dsr_enable_all_vip:
                description:
                - "Field hm_dsr_enable_all_vip"
                type: int
            pri_affinity_priority:
                description:
                - "Field pri_affinity_priority"
                type: int
            filter:
                description:
                - "Field filter"
                type: str
            sgm_list:
                description:
                - "Field sgm_list"
                type: list
            name:
                description:
                - "FW Service Name"
                type: str
            member_list:
                description:
                - "Field member_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            server_selection_fail_drop:
                description:
                - "Service selection fail drop"
                type: str
            server_selection_fail_reset:
                description:
                - "Service selection fail reset"
                type: str
            service_peak_conn:
                description:
                - "Service peak connection"
                type: str
            name:
                description:
                - "FW Service Name"
                type: str
            member_list:
                description:
                - "Field member_list"
                type: list

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
    "health_check",
    "member_list",
    "name",
    "oper",
    "protocol",
    "sampling_enable",
    "stats",
    "traffic_replication_mirror_ip_repl",
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
        'protocol': {
            'type': 'str',
            'choices': ['tcp', 'udp']
        },
        'health_check': {
            'type': 'str',
        },
        'traffic_replication_mirror_ip_repl': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'server_selection_fail_drop',
                    'server_selection_fail_reset', 'service_peak_conn'
                ]
            }
        },
        'member_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            },
            'uuid': {
                'type': 'str',
            },
            'user_tag': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'curr_conn', 'total_fwd_bytes',
                        'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts',
                        'total_conn', 'total_rev_pkts_inspected',
                        'total_rev_pkts_inspected_status_code_2xx',
                        'total_rev_pkts_inspected_status_code_non_5xx',
                        'curr_req', 'total_req', 'total_req_succ', 'peak_conn',
                        'response_time', 'fastest_rsp_time', 'slowest_rsp_time'
                    ]
                }
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type':
                'str',
                'choices': [
                    'All Up', 'Functional Up', 'Partial Up', 'Down',
                    'Disabled', 'Unknown'
                ]
            },
            'servers_up': {
                'type': 'int',
            },
            'servers_down': {
                'type': 'int',
            },
            'servers_disable': {
                'type': 'int',
            },
            'servers_total': {
                'type': 'int',
            },
            'stateless_current_rate': {
                'type': 'int',
            },
            'stateless_current_usage': {
                'type': 'int',
            },
            'stateless_state': {
                'type': 'int',
            },
            'stateless_type': {
                'type': 'int',
            },
            'hm_dsr_enable_all_vip': {
                'type': 'int',
            },
            'pri_affinity_priority': {
                'type': 'int',
            },
            'filter': {
                'type': 'str',
                'choices': ['sgm-sort-config']
            },
            'sgm_list': {
                'type': 'list',
                'sgm_name': {
                    'type': 'str',
                },
                'sgm_port': {
                    'type': 'int',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'member_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'port': {
                    'type': 'int',
                    'required': True,
                },
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['UP', 'DOWN', 'MAINTENANCE']
                    }
                }
            }
        },
        'stats': {
            'type': 'dict',
            'server_selection_fail_drop': {
                'type': 'str',
            },
            'server_selection_fail_reset': {
                'type': 'str',
            },
            'service_peak_conn': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'member_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'port': {
                    'type': 'int',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'curr_conn': {
                        'type': 'str',
                    },
                    'total_fwd_bytes': {
                        'type': 'str',
                    },
                    'total_fwd_pkts': {
                        'type': 'str',
                    },
                    'total_rev_bytes': {
                        'type': 'str',
                    },
                    'total_rev_pkts': {
                        'type': 'str',
                    },
                    'total_conn': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected_status_code_2xx': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected_status_code_non_5xx': {
                        'type': 'str',
                    },
                    'curr_req': {
                        'type': 'str',
                    },
                    'total_req': {
                        'type': 'str',
                    },
                    'total_req_succ': {
                        'type': 'str',
                    },
                    'peak_conn': {
                        'type': 'str',
                    },
                    'response_time': {
                        'type': 'str',
                    },
                    'fastest_rsp_time': {
                        'type': 'str',
                    },
                    'slowest_rsp_time': {
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
    url_base = "/axapi/v3/fw/service-group/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/fw/service-group/{name}"

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
        for k, v in payload["service-group"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["service-group"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["service-group"][k] = v
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
    payload = build_json("service-group", module)
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
