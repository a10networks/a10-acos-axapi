#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_bgp_redistribute
description:
    - Redistribute information from another routing protocol
short_description: Configures A10 router.bgp.redistribute
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
    bgp_as_number:
        description:
        - Key to identify parent object
    ip_nat_list_cfg:
        description:
        - "Field ip_nat_list_cfg"
        required: False
        suboptions:
            ip_nat_list:
                description:
                - "IP NAT list"
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
    lw4o6_cfg:
        description:
        - "Field lw4o6_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            lw4o6:
                description:
                - "LW4O6 Prefix"
    uuid:
        description:
        - "uuid of the object"
        required: False
    connected_cfg:
        description:
        - "Field connected_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            connected:
                description:
                - "Connected"
    ip_nat_cfg:
        description:
        - "Field ip_nat_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            ip_nat:
                description:
                - "IP NAT"
    floating_ip_cfg:
        description:
        - "Field floating_ip_cfg"
        required: False
        suboptions:
            floating_ip:
                description:
                - "Floating IP"
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
    isis_cfg:
        description:
        - "Field isis_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            isis:
                description:
                - "ISO IS-IS"
    vip:
        description:
        - "Field vip"
        required: False
        suboptions:
            only_not_flagged_cfg:
                description:
                - "Field only_not_flagged_cfg"
            only_flagged_cfg:
                description:
                - "Field only_flagged_cfg"
    rip_cfg:
        description:
        - "Field rip_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            rip:
                description:
                - "Routing Information Protocol (RIP)"
    ospf_cfg:
        description:
        - "Field ospf_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            ospf:
                description:
                - "Open Shortest Path First (OSPF)"
    static_cfg:
        description:
        - "Field static_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            static:
                description:
                - "Static routes"
    nat_map_cfg:
        description:
        - "Field nat_map_cfg"
        required: False
        suboptions:
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            nat_map:
                description:
                - "NAT MAP Prefix"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["connected_cfg","floating_ip_cfg","ip_nat_cfg","ip_nat_list_cfg","isis_cfg","lw4o6_cfg","nat_map_cfg","ospf_cfg","rip_cfg","static_cfg","uuid","vip",]

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
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        ip_nat_list_cfg=dict(type='dict',ip_nat_list=dict(type='bool',),route_map=dict(type='str',)),
        lw4o6_cfg=dict(type='dict',route_map=dict(type='str',),lw4o6=dict(type='bool',)),
        uuid=dict(type='str',),
        connected_cfg=dict(type='dict',route_map=dict(type='str',),connected=dict(type='bool',)),
        ip_nat_cfg=dict(type='dict',route_map=dict(type='str',),ip_nat=dict(type='bool',)),
        floating_ip_cfg=dict(type='dict',floating_ip=dict(type='bool',),route_map=dict(type='str',)),
        isis_cfg=dict(type='dict',route_map=dict(type='str',),isis=dict(type='bool',)),
        vip=dict(type='dict',only_not_flagged_cfg=dict(type='dict',route_map=dict(type='str',),only_not_flagged=dict(type='bool',)),only_flagged_cfg=dict(type='dict',route_map=dict(type='str',),only_flagged=dict(type='bool',))),
        rip_cfg=dict(type='dict',route_map=dict(type='str',),rip=dict(type='bool',)),
        ospf_cfg=dict(type='dict',route_map=dict(type='str',),ospf=dict(type='bool',)),
        static_cfg=dict(type='dict',route_map=dict(type='str',),static=dict(type='bool',)),
        nat_map_cfg=dict(type='dict',route_map=dict(type='str',),nat_map=dict(type='bool',))
    ))
   
    # Parent keys
    rv.update(dict(
        bgp_as_number=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/redistribute"

    f_dict = {}
    f_dict["bgp_as_number"] = module.params["bgp_as_number"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{bgp_as_number}/redistribute"

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
        for k, v in payload["redistribute"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["redistribute"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["redistribute"][k] = v
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
    payload = build_json("redistribute", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition and not module.check_mode:
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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()