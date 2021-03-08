#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_icmp6
description:
    - Display ICMPv6 statistics
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
                - "'all'= all; 'in_msgs'= In messages; 'in_errors'= In Errors; 'in_dest_un_reach'=
          In Destunation Unreachable; 'in_pkt_too_big'= In Packet too big;
          'in_time_exceeds'= In TTL Exceeds; 'in_param_prob'= In Parameter Problem;
          'in_echoes'= In Echo requests; 'in_exho_reply'= In Echo replies;
          'in_grp_mem_query'= In Group member query; 'in_grp_mem_resp'= In Group member
          reply; 'in_grp_mem_reduction'= In Group member reduction; 'in_router_sol'= In
          Router solicitation; 'in_ra'= In Router advertisement; 'in_ns'= In neighbor
          solicitation; 'in_na'= In neighbor advertisement; 'in_redirect'= In Redirects;
          'out_msg'= Out Messages; 'out_dst_un_reach'= Out Destination Unreachable;
          'out_pkt_too_big'= Out Packet too big; 'out_time_exceeds'= Out TTL Exceeds;
          'out_param_prob'= Out Parameter Problem; 'out_echo_req'= Out Echo requests;
          'out_echo_replies'= Out Echo replies; 'out_rs'= Out Router solicitation;
          'out_ra'= Out Router advertisement; 'out_ns'= Out neighbor solicitation;
          'out_na'= Out neighbor advertisement; 'out_redirects'= Out Redirects;
          'out_mem_resp'= Out Group member reply; 'out_mem_reductions'= Out Group member
          reduction; 'err_rs'= Error Router solicitation; 'err_ra'= Error Router
          advertisement; 'err_ns'= Error Neighbor solicitation; 'err_na'= Error Neighbor
          advertisement; 'err_redirects'= Error Redirects; 'err_echoes'= Error Echo
          requests; 'err_echo_replies'= Error Echo replies;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            in_msgs:
                description:
                - "In messages"
                type: str
            in_errors:
                description:
                - "In Errors"
                type: str
            in_dest_un_reach:
                description:
                - "In Destunation Unreachable"
                type: str
            in_pkt_too_big:
                description:
                - "In Packet too big"
                type: str
            in_time_exceeds:
                description:
                - "In TTL Exceeds"
                type: str
            in_param_prob:
                description:
                - "In Parameter Problem"
                type: str
            in_echoes:
                description:
                - "In Echo requests"
                type: str
            in_exho_reply:
                description:
                - "In Echo replies"
                type: str
            in_grp_mem_query:
                description:
                - "In Group member query"
                type: str
            in_grp_mem_resp:
                description:
                - "In Group member reply"
                type: str
            in_grp_mem_reduction:
                description:
                - "In Group member reduction"
                type: str
            in_router_sol:
                description:
                - "In Router solicitation"
                type: str
            in_ra:
                description:
                - "In Router advertisement"
                type: str
            in_ns:
                description:
                - "In neighbor solicitation"
                type: str
            in_na:
                description:
                - "In neighbor advertisement"
                type: str
            in_redirect:
                description:
                - "In Redirects"
                type: str
            out_msg:
                description:
                - "Out Messages"
                type: str
            out_dst_un_reach:
                description:
                - "Out Destination Unreachable"
                type: str
            out_pkt_too_big:
                description:
                - "Out Packet too big"
                type: str
            out_time_exceeds:
                description:
                - "Out TTL Exceeds"
                type: str
            out_param_prob:
                description:
                - "Out Parameter Problem"
                type: str
            out_echo_req:
                description:
                - "Out Echo requests"
                type: str
            out_echo_replies:
                description:
                - "Out Echo replies"
                type: str
            out_rs:
                description:
                - "Out Router solicitation"
                type: str
            out_ra:
                description:
                - "Out Router advertisement"
                type: str
            out_ns:
                description:
                - "Out neighbor solicitation"
                type: str
            out_na:
                description:
                - "Out neighbor advertisement"
                type: str
            out_redirects:
                description:
                - "Out Redirects"
                type: str
            out_mem_resp:
                description:
                - "Out Group member reply"
                type: str
            out_mem_reductions:
                description:
                - "Out Group member reduction"
                type: str
            err_rs:
                description:
                - "Error Router solicitation"
                type: str
            err_ra:
                description:
                - "Error Router advertisement"
                type: str
            err_ns:
                description:
                - "Error Neighbor solicitation"
                type: str
            err_na:
                description:
                - "Error Neighbor advertisement"
                type: str
            err_redirects:
                description:
                - "Error Redirects"
                type: str
            err_echoes:
                description:
                - "Error Echo requests"
                type: str
            err_echo_replies:
                description:
                - "Error Echo replies"
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
                    'all', 'in_msgs', 'in_errors', 'in_dest_un_reach',
                    'in_pkt_too_big', 'in_time_exceeds', 'in_param_prob',
                    'in_echoes', 'in_exho_reply', 'in_grp_mem_query',
                    'in_grp_mem_resp', 'in_grp_mem_reduction', 'in_router_sol',
                    'in_ra', 'in_ns', 'in_na', 'in_redirect', 'out_msg',
                    'out_dst_un_reach', 'out_pkt_too_big', 'out_time_exceeds',
                    'out_param_prob', 'out_echo_req', 'out_echo_replies',
                    'out_rs', 'out_ra', 'out_ns', 'out_na', 'out_redirects',
                    'out_mem_resp', 'out_mem_reductions', 'err_rs', 'err_ra',
                    'err_ns', 'err_na', 'err_redirects', 'err_echoes',
                    'err_echo_replies'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'in_msgs': {
                'type': 'str',
            },
            'in_errors': {
                'type': 'str',
            },
            'in_dest_un_reach': {
                'type': 'str',
            },
            'in_pkt_too_big': {
                'type': 'str',
            },
            'in_time_exceeds': {
                'type': 'str',
            },
            'in_param_prob': {
                'type': 'str',
            },
            'in_echoes': {
                'type': 'str',
            },
            'in_exho_reply': {
                'type': 'str',
            },
            'in_grp_mem_query': {
                'type': 'str',
            },
            'in_grp_mem_resp': {
                'type': 'str',
            },
            'in_grp_mem_reduction': {
                'type': 'str',
            },
            'in_router_sol': {
                'type': 'str',
            },
            'in_ra': {
                'type': 'str',
            },
            'in_ns': {
                'type': 'str',
            },
            'in_na': {
                'type': 'str',
            },
            'in_redirect': {
                'type': 'str',
            },
            'out_msg': {
                'type': 'str',
            },
            'out_dst_un_reach': {
                'type': 'str',
            },
            'out_pkt_too_big': {
                'type': 'str',
            },
            'out_time_exceeds': {
                'type': 'str',
            },
            'out_param_prob': {
                'type': 'str',
            },
            'out_echo_req': {
                'type': 'str',
            },
            'out_echo_replies': {
                'type': 'str',
            },
            'out_rs': {
                'type': 'str',
            },
            'out_ra': {
                'type': 'str',
            },
            'out_ns': {
                'type': 'str',
            },
            'out_na': {
                'type': 'str',
            },
            'out_redirects': {
                'type': 'str',
            },
            'out_mem_resp': {
                'type': 'str',
            },
            'out_mem_reductions': {
                'type': 'str',
            },
            'err_rs': {
                'type': 'str',
            },
            'err_ra': {
                'type': 'str',
            },
            'err_ns': {
                'type': 'str',
            },
            'err_na': {
                'type': 'str',
            },
            'err_redirects': {
                'type': 'str',
            },
            'err_echoes': {
                'type': 'str',
            },
            'err_echo_replies': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/icmp6"

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
    url_base = "/axapi/v3/system/icmp6"

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
        for k, v in payload["icmp6"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["icmp6"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["icmp6"][k] = v
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
    payload = build_json("icmp6", module)
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
