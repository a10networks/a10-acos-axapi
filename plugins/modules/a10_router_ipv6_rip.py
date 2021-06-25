#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_router_ipv6_rip
description:
    - Routing Information Protocol (RIPng)
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
    cisco_metric_behavior:
        description:
        - "'enable'= Enables updating metric consistent with Cisco; 'disable'= Disables
          updating metric consistent with Cisco;  (Enable/Disable updating metric
          consistent with Cisco)"
        type: str
        required: False
    default_information:
        description:
        - "'originate'= originate;  (Distribute default route)"
        type: str
        required: False
    default_metric:
        description:
        - "Set a metric of redistribute routes (Default metric)"
        type: int
        required: False
    recv_buffer_size:
        description:
        - "Set the RIPNG UDP receive buffer size (the RIPNG UDP receive buffer size value)"
        type: int
        required: False
    timers:
        description:
        - "Field timers"
        type: dict
        required: False
        suboptions:
            timers_cfg:
                description:
                - "Field timers_cfg"
                type: dict
    aggregate_address_cfg:
        description:
        - "Field aggregate_address_cfg"
        type: list
        required: False
        suboptions:
            aggregate_address:
                description:
                - "Set aggregate RIP route announcement (Aggregate network)"
                type: str
    route_cfg:
        description:
        - "Field route_cfg"
        type: list
        required: False
        suboptions:
            route:
                description:
                - "Static route advertisement (debugging purpose) (IP prefix)"
                type: str
    ripng_neighbor:
        description:
        - "Field ripng_neighbor"
        type: dict
        required: False
        suboptions:
            ripng_neighbor_cfg:
                description:
                - "Field ripng_neighbor_cfg"
                type: list
    passive_interface_list:
        description:
        - "Field passive_interface_list"
        type: list
        required: False
        suboptions:
            ethernet:
                description:
                - "Ethernet interface (Port number)"
                type: str
            loopback:
                description:
                - "Loopback interface (Port number)"
                type: str
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
                type: str
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
                type: str
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    distribute_list:
        description:
        - "Field distribute_list"
        type: dict
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            prefix:
                description:
                - "Field prefix"
                type: dict
    offset_list:
        description:
        - "Field offset_list"
        type: dict
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    redistribute:
        description:
        - "Field redistribute"
        type: dict
        required: False
        suboptions:
            redist_list:
                description:
                - "Field redist_list"
                type: list
            vip_list:
                description:
                - "Field vip_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    route_map:
        description:
        - "Field route_map"
        type: dict
        required: False
        suboptions:
            map_cfg:
                description:
                - "Field map_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule
import copy

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
AVAILABLE_PROPERTIES = ["aggregate_address_cfg", "cisco_metric_behavior", "default_information", "default_metric", "distribute_list", "offset_list", "passive_interface_list", "recv_buffer_size", "redistribute", "ripng_neighbor", "route_cfg", "route_map", "timers", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'cisco_metric_behavior': {'type': 'str', 'choices': ['enable', 'disable']},
        'default_information': {'type': 'str', 'choices': ['originate']},
        'default_metric': {'type': 'int', },
        'recv_buffer_size': {'type': 'int', },
        'timers': {'type': 'dict', 'timers_cfg': {'type': 'dict', 'basic': {'type': 'int', }, 'val_2': {'type': 'int', }, 'val_3': {'type': 'int', }}},
        'aggregate_address_cfg': {'type': 'list', 'aggregate_address': {'type': 'str', }},
        'route_cfg': {'type': 'list', 'route': {'type': 'str', }},
        'ripng_neighbor': {'type': 'dict', 'ripng_neighbor_cfg': {'type': 'list', 'neighbor_link_local_addr': {'type': 'str', }, 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }}},
        'passive_interface_list': {'type': 'list', 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }},
        'uuid': {'type': 'str', },
        'distribute_list': {'type': 'dict', 'acl_cfg': {'type': 'list', 'acl': {'type': 'str', }, 'acl_direction': {'type': 'str', 'choices': ['in', 'out']}, 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }}, 'uuid': {'type': 'str', }, 'prefix': {'type': 'dict', 'prefix_cfg': {'type': 'list', 'prefix_list': {'type': 'str', }, 'prefix_list_direction': {'type': 'str', 'choices': ['in', 'out']}, 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }}, 'uuid': {'type': 'str', }}},
        'offset_list': {'type': 'dict', 'acl_cfg': {'type': 'list', 'acl': {'type': 'str', }, 'offset_list_direction': {'type': 'str', 'choices': ['in', 'out']}, 'metric': {'type': 'int', }, 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }}, 'uuid': {'type': 'str', }},
        'redistribute': {'type': 'dict', 'redist_list': {'type': 'list', 'ntype': {'type': 'str', 'choices': ['bgp', 'connected', 'floating-ip', 'ip-nat-list', 'ip-nat', 'isis', 'lw4o6', 'nat-map', 'nat64', 'static-nat', 'ospf', 'static']}, 'metric': {'type': 'int', }, 'route_map': {'type': 'str', }}, 'vip_list': {'type': 'list', 'vip_type': {'type': 'str', 'choices': ['only-flagged', 'only-not-flagged']}, 'vip_metric': {'type': 'int', }, 'vip_route_map': {'type': 'str', }}, 'uuid': {'type': 'str', }},
        'route_map': {'type': 'dict', 'map_cfg': {'type': 'list', 'map': {'type': 'str', }, 'route_map_direction': {'type': 'str', 'choices': ['in', 'out']}, 'ethernet': {'type': 'str', }, 'loopback': {'type': 'str', }, 'trunk': {'type': 'str', }, 'tunnel': {'type': 'str', }, 've': {'type': 'str', }}, 'uuid': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ipv6/rip"

    f_dict = {}

    return url_base.format(**f_dict)


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
        "request_body": {"device-id": device_id},
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {"curr_part_name": a10_partition},
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))



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
    return {
        title: data
    }


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ipv6/rip"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])

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
    for k, v in payload["rip"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["rip"].get(k) != v:
            change_results["changed"] = True
            config_changes["rip"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(
                **call_result["response_body"])
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
            result["modified_values"].update(
                **call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("rip", module)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
    )

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(
            _active_partition(module, a10_partition))

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
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
