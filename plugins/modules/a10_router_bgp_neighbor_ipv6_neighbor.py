#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_bgp_neighbor_ipv6_neighbor
description:
    - Specify a ipv6 neighbor router
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
    bgp_as_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    neighbor_ipv6:
        description:
        - "Neighbor IPv6 address"
        type: str
        required: True
    nbr_remote_as:
        description:
        - "Specify AS number of BGP neighbor"
        type: int
        required: False
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
    advertisement_interval:
        description:
        - "Minimum interval between sending BGP routing updates (time in seconds)"
        type: int
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
    as_origination_interval:
        description:
        - "Minimum interval between sending AS-origination routing updates (time in
          seconds)"
        type: int
        required: False
    dynamic:
        description:
        - "Advertise dynamic capability to this neighbor"
        type: bool
        required: False
    prefix_list_direction:
        description:
        - "'both'= both; 'receive'= receive; 'send'= send;"
        type: str
        required: False
    route_refresh:
        description:
        - "Advertise route-refresh capability to this neighbor"
        type: bool
        required: False
    graceful_restart:
        description:
        - "enable graceful-restart helper for this neighbor"
        type: bool
        required: False
    extended_nexthop:
        description:
        - "Advertise extended-nexthop capability to this neighbor"
        type: bool
        required: False
    collide_established:
        description:
        - "Include Neighbor in Established State for Collision Detection"
        type: bool
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
    description:
        description:
        - "Neighbor specific description (Up to 80 characters describing this neighbor)"
        type: str
        required: False
    disallow_infinite_holdtime:
        description:
        - "BGP per neighbor disallow-infinite-holdtime"
        type: bool
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
    acos_application_only:
        description:
        - "Send BGP update to ACOS application"
        type: bool
        required: False
    dont_capability_negotiate:
        description:
        - "Do not perform capability negotiation"
        type: bool
        required: False
    ebgp_multihop:
        description:
        - "Allow EBGP neighbors not on directly connected networks"
        type: bool
        required: False
    ebgp_multihop_hop_count:
        description:
        - "maximum hop count"
        type: int
        required: False
    enforce_multihop:
        description:
        - "Enforce EBGP neighbors to perform multihop"
        type: bool
        required: False
    bfd:
        description:
        - "Bidirectional Forwarding Detection (BFD)"
        type: bool
        required: False
    multihop:
        description:
        - "Enable multihop"
        type: bool
        required: False
    key_id:
        description:
        - "Key ID"
        type: int
        required: False
    key_type:
        description:
        - "'md5'= md5; 'meticulous-md5'= meticulous-md5; 'meticulous-sha1'= meticulous-
          sha1; 'sha1'= sha1; 'simple'= simple;  (Keyed MD5/Meticulous Keyed
          MD5/Meticulous Keyed SHA1/Keyed SHA1/Simple Password)"
        type: str
        required: False
    bfd_value:
        description:
        - "Key String"
        type: str
        required: False
    bfd_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
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
    restart_min:
        description:
        - "restart value, 1 to 1440 minutes"
        type: int
        required: False
    next_hop_self:
        description:
        - "Disable the next hop calculation for this neighbor"
        type: bool
        required: False
    override_capability:
        description:
        - "Override capability negotiation result"
        type: bool
        required: False
    pass_value:
        description:
        - "Key String"
        type: str
        required: False
    pass_encrypted:
        description:
        - "Field pass_encrypted"
        type: str
        required: False
    passive:
        description:
        - "Don't send open messages to this neighbor"
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
    shutdown:
        description:
        - "Administratively shut down this neighbor"
        type: bool
        required: False
    strict_capability_match:
        description:
        - "Strict capability negotiation match"
        type: bool
        required: False
    timers_keepalive:
        description:
        - "Keepalive interval"
        type: int
        required: False
    timers_holdtime:
        description:
        - "Holdtime"
        type: int
        required: False
    connect:
        description:
        - "BGP connect timer"
        type: int
        required: False
    unsuppress_map:
        description:
        - "Route-map to selectively unsuppress suppressed routes (Name of route map)"
        type: str
        required: False
    update_source_ip:
        description:
        - "IP address"
        type: str
        required: False
    update_source_ipv6:
        description:
        - "IPv6 address"
        type: str
        required: False
    ethernet:
        description:
        - "Ethernet interface (Port number)"
        type: str
        required: False
    loopback:
        description:
        - "Loopback interface (Port number)"
        type: str
        required: False
    ve:
        description:
        - "Virtual ethernet interface (Virtual ethernet interface number)"
        type: str
        required: False
    trunk:
        description:
        - "Trunk interface (Trunk interface number)"
        type: str
        required: False
    lif:
        description:
        - "Logical interface (Lif interface name)"
        type: str
        required: False
    tunnel:
        description:
        - "Tunnel interface (Tunnel interface number)"
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "acos_application_only",
    "activate",
    "advertisement_interval",
    "allowas_in",
    "allowas_in_count",
    "as_origination_interval",
    "bfd",
    "bfd_encrypted",
    "bfd_value",
    "collide_established",
    "connect",
    "default_originate",
    "description",
    "disallow_infinite_holdtime",
    "distribute_lists",
    "dont_capability_negotiate",
    "dynamic",
    "ebgp_multihop",
    "ebgp_multihop_hop_count",
    "enforce_multihop",
    "ethernet",
    "extended_nexthop",
    "graceful_restart",
    "inbound",
    "key_id",
    "key_type",
    "lif",
    "loopback",
    "maximum_prefix",
    "maximum_prefix_thres",
    "multihop",
    "nbr_remote_as",
    "neighbor_filter_lists",
    "neighbor_ipv6",
    "neighbor_prefix_lists",
    "neighbor_route_map_lists",
    "next_hop_self",
    "override_capability",
    "pass_encrypted",
    "pass_value",
    "passive",
    "peer_group_name",
    "prefix_list_direction",
    "remove_private_as",
    "restart_min",
    "route_map",
    "route_refresh",
    "send_community_val",
    "shutdown",
    "strict_capability_match",
    "timers_holdtime",
    "timers_keepalive",
    "trunk",
    "tunnel",
    "unsuppress_map",
    "update_source_ip",
    "update_source_ipv6",
    "uuid",
    "ve",
    "weight",
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
        'neighbor_ipv6': {
            'type': 'str',
            'required': True,
        },
        'nbr_remote_as': {
            'type': 'int',
        },
        'peer_group_name': {
            'type': 'str',
        },
        'activate': {
            'type': 'bool',
        },
        'advertisement_interval': {
            'type': 'int',
        },
        'allowas_in': {
            'type': 'bool',
        },
        'allowas_in_count': {
            'type': 'int',
        },
        'as_origination_interval': {
            'type': 'int',
        },
        'dynamic': {
            'type': 'bool',
        },
        'prefix_list_direction': {
            'type': 'str',
            'choices': ['both', 'receive', 'send']
        },
        'route_refresh': {
            'type': 'bool',
        },
        'graceful_restart': {
            'type': 'bool',
        },
        'extended_nexthop': {
            'type': 'bool',
        },
        'collide_established': {
            'type': 'bool',
        },
        'default_originate': {
            'type': 'bool',
        },
        'route_map': {
            'type': 'str',
        },
        'description': {
            'type': 'str',
        },
        'disallow_infinite_holdtime': {
            'type': 'bool',
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
        'acos_application_only': {
            'type': 'bool',
        },
        'dont_capability_negotiate': {
            'type': 'bool',
        },
        'ebgp_multihop': {
            'type': 'bool',
        },
        'ebgp_multihop_hop_count': {
            'type': 'int',
        },
        'enforce_multihop': {
            'type': 'bool',
        },
        'bfd': {
            'type': 'bool',
        },
        'multihop': {
            'type': 'bool',
        },
        'key_id': {
            'type': 'int',
        },
        'key_type': {
            'type':
            'str',
            'choices':
            ['md5', 'meticulous-md5', 'meticulous-sha1', 'sha1', 'simple']
        },
        'bfd_value': {
            'type': 'str',
        },
        'bfd_encrypted': {
            'type': 'str',
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
        'restart_min': {
            'type': 'int',
        },
        'next_hop_self': {
            'type': 'bool',
        },
        'override_capability': {
            'type': 'bool',
        },
        'pass_value': {
            'type': 'str',
        },
        'pass_encrypted': {
            'type': 'str',
        },
        'passive': {
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
        'shutdown': {
            'type': 'bool',
        },
        'strict_capability_match': {
            'type': 'bool',
        },
        'timers_keepalive': {
            'type': 'int',
        },
        'timers_holdtime': {
            'type': 'int',
        },
        'connect': {
            'type': 'int',
        },
        'unsuppress_map': {
            'type': 'str',
        },
        'update_source_ip': {
            'type': 'str',
        },
        'update_source_ipv6': {
            'type': 'str',
        },
        'ethernet': {
            'type': 'str',
        },
        'loopback': {
            'type': 'str',
        },
        've': {
            'type': 'str',
        },
        'trunk': {
            'type': 'str',
        },
        'lif': {
            'type': 'str',
        },
        'tunnel': {
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
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/neighbor/ipv6-neighbor/{neighbor-ipv6}"

    f_dict = {}
    f_dict["neighbor-ipv6"] = module.params["neighbor_ipv6"]
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/neighbor/ipv6-neighbor/{neighbor-ipv6}"

    f_dict = {}
    f_dict["neighbor-ipv6"] = ""
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ipv6-neighbor"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ipv6-neighbor"].get(k) != v:
            change_results["changed"] = True
            config_changes["ipv6-neighbor"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("ipv6-neighbor", module.params,
                               AVAILABLE_PROPERTIES)
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
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "ipv6-neighbor"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "ipv6-neighbor-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
