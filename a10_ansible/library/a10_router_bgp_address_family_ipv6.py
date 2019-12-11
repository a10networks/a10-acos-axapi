#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_bgp_address_family_ipv6
description:
    - ipv6 Address family
short_description: Configures A10 router.bgp.address.family.ipv6
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    bgp_as_number:
        description:
        - Key to identify parent object
    distance:
        description:
        - "Field distance"
        required: False
        suboptions:
            distance_ext:
                description:
                - "Distance for routes external to the AS"
            distance_local:
                description:
                - "Distance for local routes"
            distance_int:
                description:
                - "Distance for routes internal to the AS"
    redistribute:
        description:
        - "Field redistribute"
        required: False
        suboptions:
            ip_nat_list_cfg:
                description:
                - "Field ip_nat_list_cfg"
            lw4o6_cfg:
                description:
                - "Field lw4o6_cfg"
            nat64_cfg:
                description:
                - "Field nat64_cfg"
            uuid:
                description:
                - "uuid of the object"
            connected_cfg:
                description:
                - "Field connected_cfg"
            ip_nat_cfg:
                description:
                - "Field ip_nat_cfg"
            floating_ip_cfg:
                description:
                - "Field floating_ip_cfg"
            isis_cfg:
                description:
                - "Field isis_cfg"
            vip:
                description:
                - "Field vip"
            rip_cfg:
                description:
                - "Field rip_cfg"
            ospf_cfg:
                description:
                - "Field ospf_cfg"
            static_cfg:
                description:
                - "Field static_cfg"
            nat_map_cfg:
                description:
                - "Field nat_map_cfg"
    aggregate_address_list:
        description:
        - "Field aggregate_address_list"
        required: False
        suboptions:
            as_set:
                description:
                - "Generate AS set path information"
            aggregate_address:
                description:
                - "Configure BGP aggregate entries (Aggregate IPv6 prefix)"
            summary_only:
                description:
                - "Filter more specific routes from updates"
    originate:
        description:
        - "Distribute an IPv6 default route"
        required: False
    maximum_paths_value:
        description:
        - "Supported BGP multipath numbers"
        required: False
    bgp:
        description:
        - "Field bgp"
        required: False
        suboptions:
            dampening_max_supress:
                description:
                - "Maximum duration to suppress a stable route(minutes)"
            dampening:
                description:
                - "Enable route-flap dampening"
            dampening_half:
                description:
                - "Reachability Half-life time for the penalty(minutes)"
            dampening_start_reuse:
                description:
                - "Value to start reusing a route"
            route_map:
                description:
                - "Route-map to specify criteria for dampening (Route-map name)"
            dampening_start_supress:
                description:
                - "Value to start suppressing a route"
            dampening_unreachability:
                description:
                - "Un-reachability Half-life time for the penalty(minutes)"
    auto_summary:
        description:
        - "Enable automatic network number summarization"
        required: False
    synchronization:
        description:
        - "Perform IGP synchronization"
        required: False
    neighbor:
        description:
        - "Field neighbor"
        required: False
        suboptions:
            peer_group_neighbor_list:
                description:
                - "Field peer_group_neighbor_list"
            ipv6_neighbor_list:
                description:
                - "Field ipv6_neighbor_list"
            ipv4_neighbor_list:
                description:
                - "Field ipv4_neighbor_list"
    uuid:
        description:
        - "uuid of the object"
        required: False
    network:
        description:
        - "Field network"
        required: False
        suboptions:
            ipv6_network_list:
                description:
                - "Field ipv6_network_list"
            synchronization:
                description:
                - "Field synchronization"

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["aggregate_address_list","auto_summary","bgp","distance","maximum_paths_value","neighbor","network","originate","redistribute","synchronization","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        distance=dict(type='dict',distance_ext=dict(type='int',),distance_local=dict(type='int',),distance_int=dict(type='int',)),
        redistribute=dict(type='dict',ip_nat_list_cfg=dict(type='dict',ip_nat_list=dict(type='bool',),route_map=dict(type='str',)),lw4o6_cfg=dict(type='dict',route_map=dict(type='str',),lw4o6=dict(type='bool',)),nat64_cfg=dict(type='dict',nat64=dict(type='bool',),route_map=dict(type='str',)),uuid=dict(type='str',),connected_cfg=dict(type='dict',route_map=dict(type='str',),connected=dict(type='bool',)),ip_nat_cfg=dict(type='dict',route_map=dict(type='str',),ip_nat=dict(type='bool',)),floating_ip_cfg=dict(type='dict',floating_ip=dict(type='bool',),route_map=dict(type='str',)),isis_cfg=dict(type='dict',route_map=dict(type='str',),isis=dict(type='bool',)),vip=dict(type='dict',only_not_flagged_cfg=dict(type='dict',route_map=dict(type='str',),only_not_flagged=dict(type='bool',)),only_flagged_cfg=dict(type='dict',route_map=dict(type='str',),only_flagged=dict(type='bool',))),rip_cfg=dict(type='dict',route_map=dict(type='str',),rip=dict(type='bool',)),ospf_cfg=dict(type='dict',route_map=dict(type='str',),ospf=dict(type='bool',)),static_cfg=dict(type='dict',route_map=dict(type='str',),static=dict(type='bool',)),nat_map_cfg=dict(type='dict',route_map=dict(type='str',),nat_map=dict(type='bool',))),
        aggregate_address_list=dict(type='list',as_set=dict(type='bool',),aggregate_address=dict(type='str',),summary_only=dict(type='bool',)),
        originate=dict(type='bool',),
        maximum_paths_value=dict(type='int',),
        bgp=dict(type='dict',dampening_max_supress=dict(type='int',),dampening=dict(type='bool',),dampening_half=dict(type='int',),dampening_start_reuse=dict(type='int',),route_map=dict(type='str',),dampening_start_supress=dict(type='int',),dampening_unreachability=dict(type='int',)),
        auto_summary=dict(type='bool',),
        synchronization=dict(type='bool',),
        neighbor=dict(type='dict',peer_group_neighbor_list=dict(type='list',maximum_prefix=dict(type='int',),neighbor_prefix_lists=dict(type='list',nbr_prefix_list_direction=dict(type='str',choices=['in','out']),nbr_prefix_list=dict(type='str',)),activate=dict(type='bool',),weight=dict(type='int',),send_community_val=dict(type='str',choices=['both','none','standard','extended']),inbound=dict(type='bool',),next_hop_self=dict(type='bool',),maximum_prefix_thres=dict(type='int',),route_map=dict(type='str',),peer_group=dict(type='str',required=True,),remove_private_as=dict(type='bool',),default_originate=dict(type='bool',),allowas_in_count=dict(type='int',),distribute_lists=dict(type='list',distribute_list_direction=dict(type='str',choices=['in','out']),distribute_list=dict(type='str',)),prefix_list_direction=dict(type='str',choices=['both','receive','send']),allowas_in=dict(type='bool',),unsuppress_map=dict(type='str',),neighbor_filter_lists=dict(type='list',filter_list=dict(type='str',),filter_list_direction=dict(type='str',choices=['in','out'])),neighbor_route_map_lists=dict(type='list',nbr_rmap_direction=dict(type='str',choices=['in','out']),nbr_route_map=dict(type='str',)),uuid=dict(type='str',)),ipv6_neighbor_list=dict(type='list',maximum_prefix=dict(type='int',),neighbor_prefix_lists=dict(type='list',nbr_prefix_list_direction=dict(type='str',choices=['in','out']),nbr_prefix_list=dict(type='str',)),allowas_in_count=dict(type='int',),neighbor_ipv6=dict(type='str',required=True,),send_community_val=dict(type='str',choices=['both','none','standard','extended']),inbound=dict(type='bool',),next_hop_self=dict(type='bool',),maximum_prefix_thres=dict(type='int',),route_map=dict(type='str',),peer_group_name=dict(type='str',),weight=dict(type='int',),unsuppress_map=dict(type='str',),prefix_list_direction=dict(type='str',choices=['both','receive','send']),default_originate=dict(type='bool',),activate=dict(type='bool',),remove_private_as=dict(type='bool',),distribute_lists=dict(type='list',distribute_list_direction=dict(type='str',choices=['in','out']),distribute_list=dict(type='str',)),allowas_in=dict(type='bool',),neighbor_route_map_lists=dict(type='list',nbr_rmap_direction=dict(type='str',choices=['in','out']),nbr_route_map=dict(type='str',)),neighbor_filter_lists=dict(type='list',filter_list=dict(type='str',),filter_list_direction=dict(type='str',choices=['in','out'])),uuid=dict(type='str',)),ipv4_neighbor_list=dict(type='list',maximum_prefix=dict(type='int',),neighbor_prefix_lists=dict(type='list',nbr_prefix_list_direction=dict(type='str',choices=['in','out']),nbr_prefix_list=dict(type='str',)),allowas_in_count=dict(type='int',),peer_group_name=dict(type='str',),send_community_val=dict(type='str',choices=['both','none','standard','extended']),neighbor_ipv4=dict(type='str',required=True,),inbound=dict(type='bool',),next_hop_self=dict(type='bool',),maximum_prefix_thres=dict(type='int',),route_map=dict(type='str',),uuid=dict(type='str',),weight=dict(type='int',),unsuppress_map=dict(type='str',),default_originate=dict(type='bool',),activate=dict(type='bool',),remove_private_as=dict(type='bool',),prefix_list_direction=dict(type='str',choices=['both','receive','send']),allowas_in=dict(type='bool',),neighbor_route_map_lists=dict(type='list',nbr_rmap_direction=dict(type='str',choices=['in','out']),nbr_route_map=dict(type='str',)),neighbor_filter_lists=dict(type='list',filter_list=dict(type='str',),filter_list_direction=dict(type='str',choices=['in','out'])),distribute_lists=dict(type='list',distribute_list_direction=dict(type='str',choices=['in','out']),distribute_list=dict(type='str',)))),
        uuid=dict(type='str',),
        network=dict(type='dict',ipv6_network_list=dict(type='list',description=dict(type='str',),route_map=dict(type='str',),comm_value=dict(type='str',),network_ipv6=dict(type='str',required=True,),backdoor=dict(type='bool',),uuid=dict(type='str',)),synchronization=dict(type='dict',network_synchronization=dict(type='bool',),uuid=dict(type='str',)))
    ))
   
    # Parent keys
    rv.update(dict(
        bgp_as_number=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/address-family/ipv6"

    f_dict = {}
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/address-family/ipv6"

    f_dict = {}
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["ipv6"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ipv6"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ipv6"][k] = v
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
    payload = build_json("ipv6", module)
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()