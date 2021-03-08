#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_pop3_proxy
description:
    - Configure POP3 Proxy global
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
                - "'all'= all; 'num'= Num; 'curr'= Current proxy conns; 'total'= Total proxy
          conns; 'svrsel_fail'= Server selection failure; 'no_route'= no route failure;
          'snat_fail'= source nat failure; 'line_too_long'= line too long;
          'line_mem_freed'= request line freed; 'invalid_start_line'= invalid start line;
          'stls'= stls cmd; 'request_dont_care'= other cmd; 'unsupported_command'=
          Unsupported cmd; 'bad_sequence'= Bad Sequence; 'rsv_persist_conn_fail'= Serv
          Sel Persist fail; 'smp_v6_fail'= Serv Sel SMPv6 fail; 'smp_v4_fail'= Serv Sel
          SMPv4 fail; 'insert_tuple_fail'= Serv Sel insert tuple fail; 'cl_est_err'=
          Client EST state erro; 'ser_connecting_err'= Serv CTNG state error;
          'server_response_err'= Serv RESP state error; 'cl_request_err'= Client RQ state
          error; 'request'= Total POP3 Request; 'control_to_ssl'= Control chn ssl;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            num:
                description:
                - "Num"
                type: str
            curr:
                description:
                - "Current proxy conns"
                type: str
            total:
                description:
                - "Total proxy conns"
                type: str
            svrsel_fail:
                description:
                - "Server selection failure"
                type: str
            no_route:
                description:
                - "no route failure"
                type: str
            snat_fail:
                description:
                - "source nat failure"
                type: str
            line_too_long:
                description:
                - "line too long"
                type: str
            line_mem_freed:
                description:
                - "request line freed"
                type: str
            invalid_start_line:
                description:
                - "invalid start line"
                type: str
            stls:
                description:
                - "stls cmd"
                type: str
            request_dont_care:
                description:
                - "other cmd"
                type: str
            unsupported_command:
                description:
                - "Unsupported cmd"
                type: str
            bad_sequence:
                description:
                - "Bad Sequence"
                type: str
            rsv_persist_conn_fail:
                description:
                - "Serv Sel Persist fail"
                type: str
            smp_v6_fail:
                description:
                - "Serv Sel SMPv6 fail"
                type: str
            smp_v4_fail:
                description:
                - "Serv Sel SMPv4 fail"
                type: str
            insert_tuple_fail:
                description:
                - "Serv Sel insert tuple fail"
                type: str
            cl_est_err:
                description:
                - "Client EST state erro"
                type: str
            ser_connecting_err:
                description:
                - "Serv CTNG state error"
                type: str
            server_response_err:
                description:
                - "Serv RESP state error"
                type: str
            cl_request_err:
                description:
                - "Client RQ state error"
                type: str
            request:
                description:
                - "Total POP3 Request"
                type: str
            control_to_ssl:
                description:
                - "Control chn ssl"
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'num', 'curr', 'total', 'svrsel_fail', 'no_route',
                    'snat_fail', 'line_too_long', 'line_mem_freed',
                    'invalid_start_line', 'stls', 'request_dont_care',
                    'unsupported_command', 'bad_sequence',
                    'rsv_persist_conn_fail', 'smp_v6_fail', 'smp_v4_fail',
                    'insert_tuple_fail', 'cl_est_err', 'ser_connecting_err',
                    'server_response_err', 'cl_request_err', 'request',
                    'control_to_ssl'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'current_proxy_conns': {
                    'type': 'int',
                },
                'total_proxy_conns': {
                    'type': 'int',
                },
                'server_selection_failure': {
                    'type': 'int',
                },
                'no_route_failure': {
                    'type': 'int',
                },
                'source_nat_failure': {
                    'type': 'int',
                },
                'stls_packet': {
                    'type': 'int',
                },
                'request_line_freed': {
                    'type': 'int',
                },
                'inv_start_line': {
                    'type': 'int',
                },
                'other_cmd': {
                    'type': 'int',
                },
                'pop3_line_too_long': {
                    'type': 'int',
                },
                'control_chn_ssl': {
                    'type': 'int',
                },
                'bad_seq': {
                    'type': 'int',
                },
                'serv_sel_persist_fail': {
                    'type': 'int',
                },
                'serv_sel_smpv6_fail': {
                    'type': 'int',
                },
                'serv_sel_smpv4_fail': {
                    'type': 'int',
                },
                'serv_sel_ins_tpl_fail': {
                    'type': 'int',
                },
                'client_est_state_err': {
                    'type': 'int',
                },
                'serv_ctng_state_err': {
                    'type': 'int',
                },
                'serv_resp_state_err': {
                    'type': 'int',
                },
                'client_rq_state_err': {
                    'type': 'int',
                },
                'total_pop3_request': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'num': {
                'type': 'str',
            },
            'curr': {
                'type': 'str',
            },
            'total': {
                'type': 'str',
            },
            'svrsel_fail': {
                'type': 'str',
            },
            'no_route': {
                'type': 'str',
            },
            'snat_fail': {
                'type': 'str',
            },
            'line_too_long': {
                'type': 'str',
            },
            'line_mem_freed': {
                'type': 'str',
            },
            'invalid_start_line': {
                'type': 'str',
            },
            'stls': {
                'type': 'str',
            },
            'request_dont_care': {
                'type': 'str',
            },
            'unsupported_command': {
                'type': 'str',
            },
            'bad_sequence': {
                'type': 'str',
            },
            'rsv_persist_conn_fail': {
                'type': 'str',
            },
            'smp_v6_fail': {
                'type': 'str',
            },
            'smp_v4_fail': {
                'type': 'str',
            },
            'insert_tuple_fail': {
                'type': 'str',
            },
            'cl_est_err': {
                'type': 'str',
            },
            'ser_connecting_err': {
                'type': 'str',
            },
            'server_response_err': {
                'type': 'str',
            },
            'cl_request_err': {
                'type': 'str',
            },
            'request': {
                'type': 'str',
            },
            'control_to_ssl': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/pop3-proxy"

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
    url_base = "/axapi/v3/slb/pop3-proxy"

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
        for k, v in payload["pop3-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["pop3-proxy"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["pop3-proxy"][k] = v
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
    payload = build_json("pop3-proxy", module)
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
