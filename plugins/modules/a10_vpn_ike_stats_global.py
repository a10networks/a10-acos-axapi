#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vpn_ike_stats_global
description:
    - IKE-stats-global statistic
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
                - "'all'= all; 'v2-init-rekey'= Initiate Rekey; 'v2-rsp-rekey'= Respond Rekey;
          'v2-child-sa-rekey'= Child SA Rekey; 'v2-in-invalid'= Incoming Invalid; 'v2-in-
          invalid-spi'= Incoming Invalid SPI; 'v2-in-init-req'= Incoming Init Request;
          'v2-in-init-rsp'= Incoming Init Response; 'v2-out-init-req'= Outgoing Init
          Request; 'v2-out-init-rsp'= Outgoing Init Response; 'v2-in-auth-req'= Incoming
          Auth Request; 'v2-in-auth-rsp'= Incoming Auth Response; 'v2-out-auth-req'=
          Outgoing Auth Request; 'v2-out-auth-rsp'= Outgoing Auth Response; 'v2-in-
          create-child-req'= Incoming Create Child Request; 'v2-in-create-child-rsp'=
          Incoming Create Child Response; 'v2-out-create-child-req'= Outgoing Create
          Child Request; 'v2-out-create-child-rsp'= Outgoing Create Child Response;
          'v2-in-info-req'= Incoming Info Request; 'v2-in-info-rsp'= Incoming Info
          Response; 'v2-out-info-req'= Outgoing Info Request; 'v2-out-info-rsp'= Outgoing
          Info Response; 'v1-in-id-prot-req'= Incoming ID Protection Request; 'v1-in-id-
          prot-rsp'= Incoming ID Protection Response; 'v1-out-id-prot-req'= Outgoing ID
          Protection Request; 'v1-out-id-prot-rsp'= Outgoing ID Protection Response;
          'v1-in-auth-only-req'= Incoming Auth Only Request; 'v1-in-auth-only-rsp'=
          Incoming Auth Only Response; 'v1-out-auth-only-req'= Outgoing Auth Only
          Request; 'v1-out-auth-only-rsp'= Outgoing Auth Only Response; 'v1-in-
          aggressive-req'= Incoming Aggressive Request; 'v1-in-aggressive-rsp'= Incoming
          Aggressive Response; 'v1-out-aggressive-req'= Outgoing Aggressive Request;
          'v1-out-aggressive-rsp'= Outgoing Aggressive Response; 'v1-in-info-v1-req'=
          Incoming Info Request; 'v1-in-info-v1-rsp'= Incoming Info Response; 'v1-out-
          info-v1-req'= Outgoing Info Request; 'v1-out-info-v1-rsp'= Outgoing Info
          Response; 'v1-in-transaction-req'= Incoming Transaction Request; 'v1-in-
          transaction-rsp'= Incoming Transaction Response; 'v1-out-transaction-req'=
          Outgoing Transaction Request; 'v1-out-transaction-rsp'= Outgoing Transaction
          Response; 'v1-in-quick-mode-req'= Incoming Quick Mode Request; 'v1-in-quick-
          mode-rsp'= Incoming Quick Mode Response; 'v1-out-quick-mode-req'= Outgoing
          Quick Mode Request; 'v1-out-quick-mode-rsp'= Outgoing Quick Mode Response;
          'v1-in-new-group-mode-req'= Incoming New Group Mode Request; 'v1-in-new-group-
          mode-rsp'= Incoming New Group Mode Response; 'v1-out-new-group-mode-req'=
          Outgoing New Group Mode Request; 'v1-out-new-group-mode-rsp'= Outgoing New
          Group Mode Response;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            v2_init_rekey:
                description:
                - "Initiate Rekey"
                type: str
            v2_rsp_rekey:
                description:
                - "Respond Rekey"
                type: str
            v2_child_sa_rekey:
                description:
                - "Child SA Rekey"
                type: str
            v2_in_invalid:
                description:
                - "Incoming Invalid"
                type: str
            v2_in_invalid_spi:
                description:
                - "Incoming Invalid SPI"
                type: str
            v2_in_init_req:
                description:
                - "Incoming Init Request"
                type: str
            v2_in_init_rsp:
                description:
                - "Incoming Init Response"
                type: str
            v2_out_init_req:
                description:
                - "Outgoing Init Request"
                type: str
            v2_out_init_rsp:
                description:
                - "Outgoing Init Response"
                type: str
            v2_in_auth_req:
                description:
                - "Incoming Auth Request"
                type: str
            v2_in_auth_rsp:
                description:
                - "Incoming Auth Response"
                type: str
            v2_out_auth_req:
                description:
                - "Outgoing Auth Request"
                type: str
            v2_out_auth_rsp:
                description:
                - "Outgoing Auth Response"
                type: str
            v2_in_create_child_req:
                description:
                - "Incoming Create Child Request"
                type: str
            v2_in_create_child_rsp:
                description:
                - "Incoming Create Child Response"
                type: str
            v2_out_create_child_req:
                description:
                - "Outgoing Create Child Request"
                type: str
            v2_out_create_child_rsp:
                description:
                - "Outgoing Create Child Response"
                type: str
            v2_in_info_req:
                description:
                - "Incoming Info Request"
                type: str
            v2_in_info_rsp:
                description:
                - "Incoming Info Response"
                type: str
            v2_out_info_req:
                description:
                - "Outgoing Info Request"
                type: str
            v2_out_info_rsp:
                description:
                - "Outgoing Info Response"
                type: str
            v1_in_id_prot_req:
                description:
                - "Incoming ID Protection Request"
                type: str
            v1_in_id_prot_rsp:
                description:
                - "Incoming ID Protection Response"
                type: str
            v1_out_id_prot_req:
                description:
                - "Outgoing ID Protection Request"
                type: str
            v1_out_id_prot_rsp:
                description:
                - "Outgoing ID Protection Response"
                type: str
            v1_in_auth_only_req:
                description:
                - "Incoming Auth Only Request"
                type: str
            v1_in_auth_only_rsp:
                description:
                - "Incoming Auth Only Response"
                type: str
            v1_out_auth_only_req:
                description:
                - "Outgoing Auth Only Request"
                type: str
            v1_out_auth_only_rsp:
                description:
                - "Outgoing Auth Only Response"
                type: str
            v1_in_aggressive_req:
                description:
                - "Incoming Aggressive Request"
                type: str
            v1_in_aggressive_rsp:
                description:
                - "Incoming Aggressive Response"
                type: str
            v1_out_aggressive_req:
                description:
                - "Outgoing Aggressive Request"
                type: str
            v1_out_aggressive_rsp:
                description:
                - "Outgoing Aggressive Response"
                type: str
            v1_in_info_v1_req:
                description:
                - "Incoming Info Request"
                type: str
            v1_in_info_v1_rsp:
                description:
                - "Incoming Info Response"
                type: str
            v1_out_info_v1_req:
                description:
                - "Outgoing Info Request"
                type: str
            v1_out_info_v1_rsp:
                description:
                - "Outgoing Info Response"
                type: str
            v1_in_transaction_req:
                description:
                - "Incoming Transaction Request"
                type: str
            v1_in_transaction_rsp:
                description:
                - "Incoming Transaction Response"
                type: str
            v1_out_transaction_req:
                description:
                - "Outgoing Transaction Request"
                type: str
            v1_out_transaction_rsp:
                description:
                - "Outgoing Transaction Response"
                type: str
            v1_in_quick_mode_req:
                description:
                - "Incoming Quick Mode Request"
                type: str
            v1_in_quick_mode_rsp:
                description:
                - "Incoming Quick Mode Response"
                type: str
            v1_out_quick_mode_req:
                description:
                - "Outgoing Quick Mode Request"
                type: str
            v1_out_quick_mode_rsp:
                description:
                - "Outgoing Quick Mode Response"
                type: str
            v1_in_new_group_mode_req:
                description:
                - "Incoming New Group Mode Request"
                type: str
            v1_in_new_group_mode_rsp:
                description:
                - "Incoming New Group Mode Response"
                type: str
            v1_out_new_group_mode_req:
                description:
                - "Outgoing New Group Mode Request"
                type: str
            v1_out_new_group_mode_rsp:
                description:
                - "Outgoing New Group Mode Response"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

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
            type='str',
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
                    'all', 'v2-init-rekey', 'v2-rsp-rekey',
                    'v2-child-sa-rekey', 'v2-in-invalid', 'v2-in-invalid-spi',
                    'v2-in-init-req', 'v2-in-init-rsp', 'v2-out-init-req',
                    'v2-out-init-rsp', 'v2-in-auth-req', 'v2-in-auth-rsp',
                    'v2-out-auth-req', 'v2-out-auth-rsp',
                    'v2-in-create-child-req', 'v2-in-create-child-rsp',
                    'v2-out-create-child-req', 'v2-out-create-child-rsp',
                    'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req',
                    'v2-out-info-rsp', 'v1-in-id-prot-req',
                    'v1-in-id-prot-rsp', 'v1-out-id-prot-req',
                    'v1-out-id-prot-rsp', 'v1-in-auth-only-req',
                    'v1-in-auth-only-rsp', 'v1-out-auth-only-req',
                    'v1-out-auth-only-rsp', 'v1-in-aggressive-req',
                    'v1-in-aggressive-rsp', 'v1-out-aggressive-req',
                    'v1-out-aggressive-rsp', 'v1-in-info-v1-req',
                    'v1-in-info-v1-rsp', 'v1-out-info-v1-req',
                    'v1-out-info-v1-rsp', 'v1-in-transaction-req',
                    'v1-in-transaction-rsp', 'v1-out-transaction-req',
                    'v1-out-transaction-rsp', 'v1-in-quick-mode-req',
                    'v1-in-quick-mode-rsp', 'v1-out-quick-mode-req',
                    'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req',
                    'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req',
                    'v1-out-new-group-mode-rsp'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'v2_init_rekey': {
                'type': 'str',
            },
            'v2_rsp_rekey': {
                'type': 'str',
            },
            'v2_child_sa_rekey': {
                'type': 'str',
            },
            'v2_in_invalid': {
                'type': 'str',
            },
            'v2_in_invalid_spi': {
                'type': 'str',
            },
            'v2_in_init_req': {
                'type': 'str',
            },
            'v2_in_init_rsp': {
                'type': 'str',
            },
            'v2_out_init_req': {
                'type': 'str',
            },
            'v2_out_init_rsp': {
                'type': 'str',
            },
            'v2_in_auth_req': {
                'type': 'str',
            },
            'v2_in_auth_rsp': {
                'type': 'str',
            },
            'v2_out_auth_req': {
                'type': 'str',
            },
            'v2_out_auth_rsp': {
                'type': 'str',
            },
            'v2_in_create_child_req': {
                'type': 'str',
            },
            'v2_in_create_child_rsp': {
                'type': 'str',
            },
            'v2_out_create_child_req': {
                'type': 'str',
            },
            'v2_out_create_child_rsp': {
                'type': 'str',
            },
            'v2_in_info_req': {
                'type': 'str',
            },
            'v2_in_info_rsp': {
                'type': 'str',
            },
            'v2_out_info_req': {
                'type': 'str',
            },
            'v2_out_info_rsp': {
                'type': 'str',
            },
            'v1_in_id_prot_req': {
                'type': 'str',
            },
            'v1_in_id_prot_rsp': {
                'type': 'str',
            },
            'v1_out_id_prot_req': {
                'type': 'str',
            },
            'v1_out_id_prot_rsp': {
                'type': 'str',
            },
            'v1_in_auth_only_req': {
                'type': 'str',
            },
            'v1_in_auth_only_rsp': {
                'type': 'str',
            },
            'v1_out_auth_only_req': {
                'type': 'str',
            },
            'v1_out_auth_only_rsp': {
                'type': 'str',
            },
            'v1_in_aggressive_req': {
                'type': 'str',
            },
            'v1_in_aggressive_rsp': {
                'type': 'str',
            },
            'v1_out_aggressive_req': {
                'type': 'str',
            },
            'v1_out_aggressive_rsp': {
                'type': 'str',
            },
            'v1_in_info_v1_req': {
                'type': 'str',
            },
            'v1_in_info_v1_rsp': {
                'type': 'str',
            },
            'v1_out_info_v1_req': {
                'type': 'str',
            },
            'v1_out_info_v1_rsp': {
                'type': 'str',
            },
            'v1_in_transaction_req': {
                'type': 'str',
            },
            'v1_in_transaction_rsp': {
                'type': 'str',
            },
            'v1_out_transaction_req': {
                'type': 'str',
            },
            'v1_out_transaction_rsp': {
                'type': 'str',
            },
            'v1_in_quick_mode_req': {
                'type': 'str',
            },
            'v1_in_quick_mode_rsp': {
                'type': 'str',
            },
            'v1_out_quick_mode_req': {
                'type': 'str',
            },
            'v1_out_quick_mode_rsp': {
                'type': 'str',
            },
            'v1_in_new_group_mode_req': {
                'type': 'str',
            },
            'v1_in_new_group_mode_rsp': {
                'type': 'str',
            },
            'v1_out_new_group_mode_req': {
                'type': 'str',
            },
            'v1_out_new_group_mode_rsp': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/ike-stats-global"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


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
    url_base = "/axapi/v3/vpn/ike-stats-global"

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ike-stats-global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ike-stats-global"].get(k) != v:
            change_results["changed"] = True
            config_changes["ike-stats-global"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("ike-stats-global", module)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
