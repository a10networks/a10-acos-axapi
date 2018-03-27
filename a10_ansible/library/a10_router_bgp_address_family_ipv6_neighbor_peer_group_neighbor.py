#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_peer-group-neighbor
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    peer-group:
        description:
            - Neighbor tag
    
    activate:
        description:
            - Enable the Address Family for this Neighbor
    
    allowas-in:
        description:
            - Accept as-path with my AS present in it
    
    allowas-in-count:
        description:
            - Number of occurrences of AS number
    
    prefix-list-direction:
        description:
            - 'both': both; 'receive': receive; 'send': send; choices:['both', 'receive', 'send']
    
    default-originate:
        description:
            - Originate default route to this neighbor
    
    route-map:
        description:
            - Route-map to specify criteria to originate default (route-map name)
    
    distribute-lists:
        
    
    neighbor-filter-lists:
        
    
    maximum-prefix:
        description:
            - Maximum number of prefix accept from this peer (maximum no. of prefix limit (various depends on model))
    
    maximum-prefix-thres:
        description:
            - threshold-value, 1 to 100 percent
    
    next-hop-self:
        description:
            - Disable the next hop calculation for this neighbor
    
    neighbor-prefix-lists:
        
    
    remove-private-as:
        description:
            - Remove private AS number from outbound updates
    
    neighbor-route-map-lists:
        
    
    send-community-val:
        description:
            - 'both': Send Standard and Extended Community attributes; 'none': Disable Sending Community attributes; 'standard': Send Standard Community attributes; 'extended': Send Extended Community attributes; choices:['both', 'none', 'standard', 'extended']
    
    inbound:
        description:
            - Allow inbound soft reconfiguration for this neighbor
    
    unsuppress-map:
        description:
            - Route-map to selectively unsuppress suppressed routes (Name of route map)
    
    weight:
        description:
            - Set default weight for routes from this neighbor
    
    uuid:
        description:
            - uuid of the object
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"activate","allowas_in","allowas_in_count","default_originate","distribute_lists","inbound","maximum_prefix","maximum_prefix_thres","neighbor_filter_lists","neighbor_prefix_lists","neighbor_route_map_lists","next_hop_self","peer_group","prefix_list_direction","remove_private_as","route_map","send_community_val","unsuppress_map","uuid","weight",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        activate=dict(
            type='str' 
        ),
        allowas_in=dict(
            type='str' 
        ),
        allowas_in_count=dict(
            type='str' 
        ),
        default_originate=dict(
            type='str' 
        ),
        distribute_lists=dict(
            type='str' 
        ),
        inbound=dict(
            type='str' 
        ),
        maximum_prefix=dict(
            type='str' 
        ),
        maximum_prefix_thres=dict(
            type='str' 
        ),
        neighbor_filter_lists=dict(
            type='str' 
        ),
        neighbor_prefix_lists=dict(
            type='str' 
        ),
        neighbor_route_map_lists=dict(
            type='str' 
        ),
        next_hop_self=dict(
            type='str' 
        ),
        peer_group=dict(
            type='str' , required=True
        ),
        prefix_list_direction=dict(
            type='enum' , choices=['both', 'receive', 'send']
        ),
        remove_private_as=dict(
            type='str' 
        ),
        route_map=dict(
            type='str' 
        ),
        send_community_val=dict(
            type='enum' , choices=['both', 'none', 'standard', 'extended']
        ),
        unsuppress_map=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        weight=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{as-number}/address-family/ipv6/neighbor/peer-group-neighbor/{peer-group}"
    f_dict = {}
    
    f_dict["peer-group"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{as-number}/address-family/ipv6/neighbor/peer-group-neighbor/{peer-group}"
    f_dict = {}
    
    f_dict["peer-group"] = module.params["peer-group"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("peer-group-neighbor", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
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

def update(module, result):
    payload = build_json("peer-group-neighbor", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)



def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()