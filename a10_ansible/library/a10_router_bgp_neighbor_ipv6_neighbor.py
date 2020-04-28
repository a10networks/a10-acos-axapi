#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_router_bgp_neighbor_ipv6_neighbor
description:
    - Specify a ipv6 neighbor router
short_description: Configures A10 router.bgp.neighbor.ipv6-neighbor
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - present
          - absent
          - noop
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    bgp_as_number:
        description:
        - Key to identify parent object
    activate:
        description:
        - "Enable the Address Family for this Neighbor"
        required: False
    route_refresh:
        description:
        - "Advertise route-refresh capability to this neighbor"
        required: False
    ve:
        description:
        - "Virtual ethernet interface (Virtual ethernet interface number)"
        required: False
    weight:
        description:
        - "Set default weight for routes from this neighbor"
        required: False
    timers_keepalive:
        description:
        - "Keepalive interval"
        required: False
    bfd_value:
        description:
        - "Key String"
        required: False
    key_type:
        description:
        - "'md5'= md5; 'meticulous-md5'= meticulous-md5; 'meticulous-sha1'= meticulous-sha1; 'sha1'= sha1; 'simple'= simple;  (Keyed MD5/Meticulous Keyed MD5/Meticulous Keyed SHA1/Keyed SHA1/Simple Password)"
        required: False
    dynamic:
        description:
        - "Advertise dynamic capability to this neighbor"
        required: False
    multihop:
        description:
        - "Enable multihop"
        required: False
    default_originate:
        description:
        - "Originate default route to this neighbor"
        required: False
    distribute_lists:
        description:
        - "Field distribute_lists"
        required: False
        suboptions:
            distribute_list_direction:
                description:
                - "'in'= in; 'out'= out; "
            distribute_list:
                description:
                - "Filter updates to/from this neighbor (IP standard/extended/named access list)"
    shutdown:
        description:
        - "Administratively shut down this neighbor"
        required: False
    enforce_multihop:
        description:
        - "Enforce EBGP neighbors to perform multihop"
        required: False
    prefix_list_direction:
        description:
        - "'both'= both; 'receive'= receive; 'send'= send; "
        required: False
    nbr_remote_as:
        description:
        - "Specify AS number of BGP neighbor"
        required: False
    neighbor_ipv6:
        description:
        - "Neighbor IPv6 address"
        required: True
    advertisement_interval:
        description:
        - "Minimum interval between sending BGP routing updates (time in seconds)"
        required: False
    lif:
        description:
        - "Logical interface (Lif interface number)"
        required: False
    neighbor_route_map_lists:
        description:
        - "Field neighbor_route_map_lists"
        required: False
        suboptions:
            nbr_rmap_direction:
                description:
                - "'in'= in; 'out'= out; "
            nbr_route_map:
                description:
                - "Apply route map to neighbor (Name of route map)"
    uuid:
        description:
        - "uuid of the object"
        required: False
    send_community_val:
        description:
        - "'both'= Send Standard and Extended Community attributes; 'none'= Disable Sending Community attributes; 'standard'= Send Standard Community attributes; 'extended'= Send Extended Community attributes; "
        required: False
    loopback:
        description:
        - "Loopback interface (Port number)"
        required: False
    collide_established:
        description:
        - "Include Neighbor in Established State for Collision Detection"
        required: False
    next_hop_self:
        description:
        - "Disable the next hop calculation for this neighbor"
        required: False
    pass_encrypted:
        description:
        - "Field pass_encrypted"
        required: False
    dont_capability_negotiate:
        description:
        - "Do not perform capability negotiation"
        required: False
    unsuppress_map:
        description:
        - "Route-map to selectively unsuppress suppressed routes (Name of route map)"
        required: False
    passive:
        description:
        - "Don't send open messages to this neighbor"
        required: False
    ebgp_multihop_hop_count:
        description:
        - "maximum hop count"
        required: False
    allowas_in:
        description:
        - "Accept as-path with my AS present in it"
        required: False
    acos_application_only:
        description:
        - "Send BGP update to ACOS application"
        required: False
    pass_value:
        description:
        - "Key String"
        required: False
    key_id:
        description:
        - "Key ID"
        required: False
    timers_holdtime:
        description:
        - "Holdtime"
        required: False
    update_source_ip:
        description:
        - "IP address"
        required: False
    description:
        description:
        - "Neighbor specific description (Up to 80 characters describing this neighbor)"
        required: False
    inbound:
        description:
        - "Allow inbound soft reconfiguration for this neighbor"
        required: False
    maximum_prefix_thres:
        description:
        - "threshold-value, 1 to 100 percent"
        required: False
    bfd_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
        required: False
    disallow_infinite_holdtime:
        description:
        - "BGP per neighbor disallow-infinite-holdtime"
        required: False
    route_map:
        description:
        - "Route-map to specify criteria to originate default (route-map name)"
        required: False
    trunk:
        description:
        - "Trunk interface (Trunk interface number)"
        required: False
    remove_private_as:
        description:
        - "Remove private AS number from outbound updates"
        required: False
    neighbor_filter_lists:
        description:
        - "Field neighbor_filter_lists"
        required: False
        suboptions:
            filter_list:
                description:
                - "Establish BGP filters (AS path access-list name)"
            filter_list_direction:
                description:
                - "'in'= in; 'out'= out; "
    update_source_ipv6:
        description:
        - "IPv6 address"
        required: False
    maximum_prefix:
        description:
        - "Maximum number of prefix accept from this peer (maximum no. of prefix limit (various depends on model))"
        required: False
    neighbor_prefix_lists:
        description:
        - "Field neighbor_prefix_lists"
        required: False
        suboptions:
            nbr_prefix_list_direction:
                description:
                - "'in'= in; 'out'= out; "
            nbr_prefix_list:
                description:
                - "Filter updates to/from this neighbor (Name of a prefix list)"
    allowas_in_count:
        description:
        - "Number of occurrences of AS number"
        required: False
    peer_group_name:
        description:
        - "Configure peer-group (peer-group name)"
        required: False
    as_origination_interval:
        description:
        - "Minimum interval between sending AS-origination routing updates (time in seconds)"
        required: False
    override_capability:
        description:
        - "Override capability negotiation result"
        required: False
    bfd:
        description:
        - "Bidirectional Forwarding Detection (BFD)"
        required: False
    tunnel:
        description:
        - "Tunnel interface (Tunnel interface number)"
        required: False
    strict_capability_match:
        description:
        - "Strict capability negotiation match"
        required: False
    ebgp_multihop:
        description:
        - "Allow EBGP neighbors not on directly connected networks"
        required: False
    ethernet:
        description:
        - "Ethernet interface (Port number)"
        required: False
    connect:
        description:
        - "BGP connect timer"
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
AVAILABLE_PROPERTIES = ["acos_application_only","activate","advertisement_interval","allowas_in","allowas_in_count","as_origination_interval","bfd","bfd_encrypted","bfd_value","collide_established","connect","default_originate","description","disallow_infinite_holdtime","distribute_lists","dont_capability_negotiate","dynamic","ebgp_multihop","ebgp_multihop_hop_count","enforce_multihop","ethernet","inbound","key_id","key_type","lif","loopback","maximum_prefix","maximum_prefix_thres","multihop","nbr_remote_as","neighbor_filter_lists","neighbor_ipv6","neighbor_prefix_lists","neighbor_route_map_lists","next_hop_self","override_capability","pass_encrypted","pass_value","passive","peer_group_name","prefix_list_direction","remove_private_as","route_map","route_refresh","send_community_val","shutdown","strict_capability_match","timers_holdtime","timers_keepalive","trunk","tunnel","unsuppress_map","update_source_ip","update_source_ipv6","uuid","ve","weight",]

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
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        activate=dict(type='bool',),
        route_refresh=dict(type='bool',),
        ve=dict(type='str',),
        weight=dict(type='int',),
        timers_keepalive=dict(type='int',),
        bfd_value=dict(type='str',),
        key_type=dict(type='str',choices=['md5','meticulous-md5','meticulous-sha1','sha1','simple']),
        dynamic=dict(type='bool',),
        multihop=dict(type='bool',),
        default_originate=dict(type='bool',),
        distribute_lists=dict(type='list',distribute_list_direction=dict(type='str',choices=['in','out']),distribute_list=dict(type='str',)),
        shutdown=dict(type='bool',),
        enforce_multihop=dict(type='bool',),
        prefix_list_direction=dict(type='str',choices=['both','receive','send']),
        nbr_remote_as=dict(type='int',),
        neighbor_ipv6=dict(type='str',required=True,),
        advertisement_interval=dict(type='int',),
        lif=dict(type='int',),
        neighbor_route_map_lists=dict(type='list',nbr_rmap_direction=dict(type='str',choices=['in','out']),nbr_route_map=dict(type='str',)),
        uuid=dict(type='str',),
        send_community_val=dict(type='str',choices=['both','none','standard','extended']),
        loopback=dict(type='str',),
        collide_established=dict(type='bool',),
        next_hop_self=dict(type='bool',),
        pass_encrypted=dict(type='str',),
        dont_capability_negotiate=dict(type='bool',),
        unsuppress_map=dict(type='str',),
        passive=dict(type='bool',),
        ebgp_multihop_hop_count=dict(type='int',),
        allowas_in=dict(type='bool',),
        acos_application_only=dict(type='bool',),
        pass_value=dict(type='str',),
        key_id=dict(type='int',),
        timers_holdtime=dict(type='int',),
        update_source_ip=dict(type='str',),
        description=dict(type='str',),
        inbound=dict(type='bool',),
        maximum_prefix_thres=dict(type='int',),
        bfd_encrypted=dict(type='str',),
        disallow_infinite_holdtime=dict(type='bool',),
        route_map=dict(type='str',),
        trunk=dict(type='str',),
        remove_private_as=dict(type='bool',),
        neighbor_filter_lists=dict(type='list',filter_list=dict(type='str',),filter_list_direction=dict(type='str',choices=['in','out'])),
        update_source_ipv6=dict(type='str',),
        maximum_prefix=dict(type='int',),
        neighbor_prefix_lists=dict(type='list',nbr_prefix_list_direction=dict(type='str',choices=['in','out']),nbr_prefix_list=dict(type='str',)),
        allowas_in_count=dict(type='int',),
        peer_group_name=dict(type='str',),
        as_origination_interval=dict(type='int',),
        override_capability=dict(type='bool',),
        bfd=dict(type='bool',),
        tunnel=dict(type='str',),
        strict_capability_match=dict(type='bool',),
        ebgp_multihop=dict(type='bool',),
        ethernet=dict(type='str',),
        connect=dict(type='int',)
    ))
   
    # Parent keys
    rv.update(dict(
        bgp_as_number=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/neighbor/ipv6-neighbor/{neighbor-ipv6}"

    f_dict = {}
    f_dict["neighbor-ipv6"] = module.params["neighbor_ipv6"]
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/neighbor/ipv6-neighbor/{neighbor-ipv6}"

    f_dict = {}
    f_dict["neighbor-ipv6"] = ""
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

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
        for k, v in payload["ipv6-neighbor"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ipv6-neighbor"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ipv6-neighbor"][k] = v
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
    payload = build_json("ipv6-neighbor", module)
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
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