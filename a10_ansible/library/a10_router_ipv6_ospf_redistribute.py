#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_ipv6_ospf_redistribute
description:
    - Redistribute information from another routing protocol
short_description: Configures A10 router.ipv6.ospf.redistribute
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
    partition:
        description:
        - Destination/target partition for object/command
    ospf_process_id:
        description:
        - Key to identify parent object
    redist_list:
        description:
        - "Field redist_list"
        required: False
        suboptions:
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            ntype:
                description:
                - "'bgp'= Border Gateway Protocol (BGP); 'connected'= Connected; 'floating-ip'= Floating IP; 'ip-nat-list'= IP NAT list; 'nat-map'= NAT MAP Prefix; 'nat64'= NAT64 Prefix; 'lw4o6'= LW4O6 Prefix; 'isis'= ISO IS-IS; 'rip'= Routing Information Protocol (RIP); 'static'= Static routes; "
            metric_type:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics; "
    ospf_list:
        description:
        - "Field ospf_list"
        required: False
        suboptions:
            route_map_ospf:
                description:
                - "Route map reference (Pointer to route-map entries)"
            metric_ospf:
                description:
                - "OSPF default metric (OSPF metric)"
            metric_type_ospf:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics; "
            ospf:
                description:
                - "Open Shortest Path First (OSPF)"
            process_id:
                description:
                - "OSPF process ID"
    uuid:
        description:
        - "uuid of the object"
        required: False
    ip_nat_floating_list:
        description:
        - "Field ip_nat_floating_list"
        required: False
        suboptions:
            ip_nat_floating_IP_forward:
                description:
                - "Floating-IP as forward address"
            ip_nat_prefix:
                description:
                - "Address"
    vip_list:
        description:
        - "Field vip_list"
        required: False
        suboptions:
            metric_vip:
                description:
                - "OSPF default metric (OSPF metric)"
            metric_type_vip:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics; "
            type_vip:
                description:
                - "'only-flagged'= Selected Virtual IP (VIP); 'only-not-flagged'= Only not flagged; "
            route_map_vip:
                description:
                - "Route map reference (Pointer to route-map entries)"
    ip_nat:
        description:
        - "IP-NAT"
        required: False
    metric_ip_nat:
        description:
        - "OSPF default metric (OSPF metric)"
        required: False
    route_map_ip_nat:
        description:
        - "Route map reference (Pointer to route-map entries)"
        required: False
    vip_floating_list:
        description:
        - "Field vip_floating_list"
        required: False
        suboptions:
            vip_address:
                description:
                - "Address"
            vip_floating_IP_forward:
                description:
                - "Floating-IP as forward address"
    metric_type_ip_nat:
        description:
        - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics; "
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
AVAILABLE_PROPERTIES = ["ip_nat","ip_nat_floating_list","metric_ip_nat","metric_type_ip_nat","ospf_list","redist_list","route_map_ip_nat","uuid","vip_floating_list","vip_list",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        redist_list=dict(type='list',metric=dict(type='int',),route_map=dict(type='str',),ntype=dict(type='str',choices=['bgp','connected','floating-ip','ip-nat-list','nat-map','nat64','lw4o6','isis','rip','static']),metric_type=dict(type='str',choices=['1','2'])),
        ospf_list=dict(type='list',route_map_ospf=dict(type='str',),metric_ospf=dict(type='int',),metric_type_ospf=dict(type='str',choices=['1','2']),ospf=dict(type='bool',),process_id=dict(type='str',)),
        uuid=dict(type='str',),
        ip_nat_floating_list=dict(type='list',ip_nat_floating_IP_forward=dict(type='str',),ip_nat_prefix=dict(type='str',)),
        vip_list=dict(type='list',metric_vip=dict(type='int',),metric_type_vip=dict(type='str',choices=['1','2']),type_vip=dict(type='str',choices=['only-flagged','only-not-flagged']),route_map_vip=dict(type='str',)),
        ip_nat=dict(type='bool',),
        metric_ip_nat=dict(type='int',),
        route_map_ip_nat=dict(type='str',),
        vip_floating_list=dict(type='list',vip_address=dict(type='str',),vip_floating_IP_forward=dict(type='str',)),
        metric_type_ip_nat=dict(type='str',choices=['1','2'])
    ))
   
    # Parent keys
    rv.update(dict(
        ospf_process_id=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ipv6/ospf/{ospf_process_id}/redistribute"

    f_dict = {}
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ipv6/ospf/{ospf_process_id}/redistribute"

    f_dict = {}
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

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
        if v:
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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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
        return False

def create(module, result):
    payload = build_json("redistribute", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
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
    payload = build_json("redistribute", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("redistribute", module)
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
    
    partition = module.params["partition"]

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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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