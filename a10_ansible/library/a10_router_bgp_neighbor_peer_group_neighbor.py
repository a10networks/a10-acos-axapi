#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_bgp_neighbor_peer_group_neighbor
description:
    - None
short_description: Configures A10 router.bgp.neighbor.peer-group-neighbor
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
    activate:
        description:
        - "None"
        required: False
    route_refresh:
        description:
        - "None"
        required: False
    ve:
        description:
        - "None"
        required: False
    weight:
        description:
        - "None"
        required: False
    timers_keepalive:
        description:
        - "None"
        required: False
    dynamic:
        description:
        - "None"
        required: False
    default_originate:
        description:
        - "None"
        required: False
    distribute_lists:
        description:
        - "Field distribute_lists"
        required: False
        suboptions:
            distribute_list_direction:
                description:
                - "None"
            distribute_list:
                description:
                - "None"
    shutdown:
        description:
        - "None"
        required: False
    enforce_multihop:
        description:
        - "None"
        required: False
    prefix_list_direction:
        description:
        - "None"
        required: False
    neighbor_route_map_lists:
        description:
        - "Field neighbor_route_map_lists"
        required: False
        suboptions:
            nbr_rmap_direction:
                description:
                - "None"
            nbr_route_map:
                description:
                - "None"
    advertisement_interval:
        description:
        - "None"
        required: False
    lif:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    send_community_val:
        description:
        - "None"
        required: False
    loopback:
        description:
        - "None"
        required: False
    collide_established:
        description:
        - "None"
        required: False
    next_hop_self:
        description:
        - "None"
        required: False
    pass_encrypted:
        description:
        - "Field pass_encrypted"
        required: False
    peer_group:
        description:
        - "None"
        required: True
    dont_capability_negotiate:
        description:
        - "None"
        required: False
    unsuppress_map:
        description:
        - "None"
        required: False
    passive:
        description:
        - "None"
        required: False
    ebgp_multihop_hop_count:
        description:
        - "None"
        required: False
    allowas_in:
        description:
        - "None"
        required: False
    pass_value:
        description:
        - "None"
        required: False
    timers_holdtime:
        description:
        - "None"
        required: False
    description:
        description:
        - "None"
        required: False
    inbound:
        description:
        - "None"
        required: False
    maximum_prefix_thres:
        description:
        - "None"
        required: False
    peer_group_key:
        description:
        - "None"
        required: False
    peer_group_remote_as:
        description:
        - "None"
        required: False
    disallow_infinite_holdtime:
        description:
        - "None"
        required: False
    route_map:
        description:
        - "None"
        required: False
    trunk:
        description:
        - "None"
        required: False
    remove_private_as:
        description:
        - "None"
        required: False
    neighbor_filter_lists:
        description:
        - "Field neighbor_filter_lists"
        required: False
        suboptions:
            filter_list:
                description:
                - "None"
            filter_list_direction:
                description:
                - "None"
    update_source_ipv6:
        description:
        - "None"
        required: False
    maximum_prefix:
        description:
        - "None"
        required: False
    neighbor_prefix_lists:
        description:
        - "Field neighbor_prefix_lists"
        required: False
        suboptions:
            nbr_prefix_list_direction:
                description:
                - "None"
            nbr_prefix_list:
                description:
                - "None"
    allowas_in_count:
        description:
        - "None"
        required: False
    as_origination_interval:
        description:
        - "None"
        required: False
    override_capability:
        description:
        - "None"
        required: False
    update_source_ip:
        description:
        - "None"
        required: False
    tunnel:
        description:
        - "None"
        required: False
    strict_capability_match:
        description:
        - "None"
        required: False
    ebgp_multihop:
        description:
        - "None"
        required: False
    ethernet:
        description:
        - "None"
        required: False
    connect:
        description:
        - "None"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["activate","advertisement_interval","allowas_in","allowas_in_count","as_origination_interval","collide_established","connect","default_originate","description","disallow_infinite_holdtime","distribute_lists","dont_capability_negotiate","dynamic","ebgp_multihop","ebgp_multihop_hop_count","enforce_multihop","ethernet","inbound","lif","loopback","maximum_prefix","maximum_prefix_thres","neighbor_filter_lists","neighbor_prefix_lists","neighbor_route_map_lists","next_hop_self","override_capability","pass_encrypted","pass_value","passive","peer_group","peer_group_key","peer_group_remote_as","prefix_list_direction","remove_private_as","route_map","route_refresh","send_community_val","shutdown","strict_capability_match","timers_holdtime","timers_keepalive","trunk","tunnel","unsuppress_map","update_source_ip","update_source_ipv6","uuid","ve","weight",]

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
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        activate=dict(type='bool',),
        route_refresh=dict(type='bool',),
        ve=dict(type='str',),
        weight=dict(type='int',),
        timers_keepalive=dict(type='int',),
        dynamic=dict(type='bool',),
        default_originate=dict(type='bool',),
        distribute_lists=dict(type='list',distribute_list_direction=dict(type='str',choices=['in','out']),distribute_list=dict(type='str',)),
        shutdown=dict(type='bool',),
        enforce_multihop=dict(type='bool',),
        prefix_list_direction=dict(type='str',choices=['both','receive','send']),
        neighbor_route_map_lists=dict(type='list',nbr_rmap_direction=dict(type='str',choices=['in','out']),nbr_route_map=dict(type='str',)),
        advertisement_interval=dict(type='int',),
        lif=dict(type='int',),
        uuid=dict(type='str',),
        send_community_val=dict(type='str',choices=['both','none','standard','extended']),
        loopback=dict(type='str',),
        collide_established=dict(type='bool',),
        next_hop_self=dict(type='bool',),
        pass_encrypted=dict(type='str',),
        peer_group=dict(type='str',required=True,),
        dont_capability_negotiate=dict(type='bool',),
        unsuppress_map=dict(type='str',),
        passive=dict(type='bool',),
        ebgp_multihop_hop_count=dict(type='int',),
        allowas_in=dict(type='bool',),
        pass_value=dict(type='str',),
        timers_holdtime=dict(type='int',),
        description=dict(type='str',),
        inbound=dict(type='bool',),
        maximum_prefix_thres=dict(type='int',),
        peer_group_key=dict(type='bool',),
        peer_group_remote_as=dict(type='int',),
        disallow_infinite_holdtime=dict(type='bool',),
        route_map=dict(type='str',),
        trunk=dict(type='str',),
        remove_private_as=dict(type='bool',),
        neighbor_filter_lists=dict(type='list',filter_list=dict(type='str',),filter_list_direction=dict(type='str',choices=['in','out'])),
        update_source_ipv6=dict(type='str',),
        maximum_prefix=dict(type='int',),
        neighbor_prefix_lists=dict(type='list',nbr_prefix_list_direction=dict(type='str',choices=['in','out']),nbr_prefix_list=dict(type='str',)),
        allowas_in_count=dict(type='int',),
        as_origination_interval=dict(type='int',),
        override_capability=dict(type='bool',),
        update_source_ip=dict(type='str',),
        tunnel=dict(type='str',),
        strict_capability_match=dict(type='bool',),
        ebgp_multihop=dict(type='bool',),
        ethernet=dict(type='str',),
        connect=dict(type='int',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{as-number}/neighbor/peer-group-neighbor/{peer-group}"
    f_dict = {}
    f_dict["peer-group"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{as-number}/neighbor/peer-group-neighbor/{peer-group}"
    f_dict = {}
    f_dict["peer-group"] = module.params["peer-group"]

    return url_base.format(**f_dict)


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
        if isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
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

def update(module, result, existing_config):
    payload = build_json("peer-group-neighbor", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

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
    partition = module.params["partition"]

    # TODO(remove hardcoded port #)
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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