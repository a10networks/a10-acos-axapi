#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_bgp_address_family_ipv6_neighbor_ipv4_neighbor
description:
    - Specify a peer-group neighbor router
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    bgp_as_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    neighbor_ipv4:
        description:
        - "Neighbor address"
        type: str
        required: True
    peer_group_name:
        description:
        - "Configure peer-group (peer-group name)"
        type: str
        required: False
    activate:
        description:
        - "Enable the Address Family for this Neighbor"
        type: bool
        required: False
    allowas_in:
        description:
        - "Accept as-path with my AS present in it"
        type: bool
        required: False
    allowas_in_count:
        description:
        - "Number of occurrences of AS number"
        type: int
        required: False
    prefix_list_direction:
        description:
        - "'both'= both; 'receive'= receive; 'send'= send;"
        type: str
        required: False
    default_originate:
        description:
        - "Originate default route to this neighbor"
        type: bool
        required: False
    route_map:
        description:
        - "Route-map to specify criteria to originate default (route-map name)"
        type: str
        required: False
    distribute_lists:
        description:
        - "Field distribute_lists"
        type: list
        required: False
        suboptions:
            distribute_list:
                description:
                - "Filter updates to/from this neighbor (IP standard/extended/named access list)"
                type: str
            distribute_list_direction:
                description:
                - "'in'= in; 'out'= out;"
                type: str
    neighbor_filter_lists:
        description:
        - "Field neighbor_filter_lists"
        type: list
        required: False
        suboptions:
            filter_list:
                description:
                - "Establish BGP filters (AS path access-list name)"
                type: str
            filter_list_direction:
                description:
                - "'in'= in; 'out'= out;"
                type: str
    maximum_prefix:
        description:
        - "Maximum number of prefix accept from this peer (maximum no. of prefix limit
          (various depends on model))"
        type: int
        required: False
    maximum_prefix_thres:
        description:
        - "threshold-value, 1 to 100 percent"
        type: int
        required: False
    next_hop_self:
        description:
        - "Disable the next hop calculation for this neighbor"
        type: bool
        required: False
    neighbor_prefix_lists:
        description:
        - "Field neighbor_prefix_lists"
        type: list
        required: False
        suboptions:
            nbr_prefix_list:
                description:
                - "Filter updates to/from this neighbor (Name of a prefix list)"
                type: str
            nbr_prefix_list_direction:
                description:
                - "'in'= in; 'out'= out;"
                type: str
    remove_private_as:
        description:
        - "Remove private AS number from outbound updates"
        type: bool
        required: False
    neighbor_route_map_lists:
        description:
        - "Field neighbor_route_map_lists"
        type: list
        required: False
        suboptions:
            nbr_route_map:
                description:
                - "Apply route map to neighbor (Name of route map)"
                type: str
            nbr_rmap_direction:
                description:
                - "'in'= in; 'out'= out;"
                type: str
    send_community_val:
        description:
        - "'both'= Send Standard and Extended Community attributes; 'none'= Disable
          Sending Community attributes; 'standard'= Send Standard Community attributes;
          'extended'= Send Extended Community attributes;"
        type: str
        required: False
    inbound:
        description:
        - "Allow inbound soft reconfiguration for this neighbor"
        type: bool
        required: False
    unsuppress_map:
        description:
        - "Route-map to selectively unsuppress suppressed routes (Name of route map)"
        type: str
        required: False
    weight:
        description:
        - "Set default weight for routes from this neighbor"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "activate",
    "allowas_in",
    "allowas_in_count",
    "default_originate",
    "distribute_lists",
    "inbound",
    "maximum_prefix",
    "maximum_prefix_thres",
    "neighbor_filter_lists",
    "neighbor_ipv4",
    "neighbor_prefix_lists",
    "neighbor_route_map_lists",
    "next_hop_self",
    "peer_group_name",
    "prefix_list_direction",
    "remove_private_as",
    "route_map",
    "send_community_val",
    "unsuppress_map",
    "uuid",
    "weight",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'neighbor_ipv4': {
            'type': 'str',
            'required': True,
        },
        'peer_group_name': {
            'type': 'str',
        },
        'activate': {
            'type': 'bool',
        },
        'allowas_in': {
            'type': 'bool',
        },
        'allowas_in_count': {
            'type': 'int',
        },
        'prefix_list_direction': {
            'type': 'str',
            'choices': ['both', 'receive', 'send']
        },
        'default_originate': {
            'type': 'bool',
        },
        'route_map': {
            'type': 'str',
        },
        'distribute_lists': {
            'type': 'list',
            'distribute_list': {
                'type': 'str',
            },
            'distribute_list_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            }
        },
        'neighbor_filter_lists': {
            'type': 'list',
            'filter_list': {
                'type': 'str',
            },
            'filter_list_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            }
        },
        'maximum_prefix': {
            'type': 'int',
        },
        'maximum_prefix_thres': {
            'type': 'int',
        },
        'next_hop_self': {
            'type': 'bool',
        },
        'neighbor_prefix_lists': {
            'type': 'list',
            'nbr_prefix_list': {
                'type': 'str',
            },
            'nbr_prefix_list_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            }
        },
        'remove_private_as': {
            'type': 'bool',
        },
        'neighbor_route_map_lists': {
            'type': 'list',
            'nbr_route_map': {
                'type': 'str',
            },
            'nbr_rmap_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            }
        },
        'send_community_val': {
            'type': 'str',
            'choices': ['both', 'none', 'standard', 'extended']
        },
        'inbound': {
            'type': 'bool',
        },
        'unsuppress_map': {
            'type': 'str',
        },
        'weight': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(bgp_as_number=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/address-family/ipv6/neighbor/ipv4-neighbor/{neighbor-ipv4}"

    f_dict = {}
    f_dict["neighbor-ipv4"] = module.params["neighbor_ipv4"]
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

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
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/address-family/ipv6/neighbor/ipv4-neighbor/{neighbor-ipv4}"

    f_dict = {}
    f_dict["neighbor-ipv4"] = ""
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

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
    for k, v in payload["ipv4-neighbor"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ipv4-neighbor"].get(k) != v:
            change_results["changed"] = True
            config_changes["ipv4-neighbor"][k] = v

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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("ipv4-neighbor", module)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


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
    finally:
        module.client.session.close()
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

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
