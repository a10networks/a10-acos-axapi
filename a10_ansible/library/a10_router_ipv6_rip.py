#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_ipv6_rip
description:
    - Routing Information Protocol (RIPng)
short_description: Configures A10 router.ipv6.rip
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
    default_metric:
        description:
        - "Set a metric of redistribute routes (Default metric)"
        required: False
    recv_buffer_size:
        description:
        - "Set the RIPNG UDP receive buffer size (the RIPNG UDP receive buffer size value)"
        required: False
    cisco_metric_behavior:
        description:
        - "'enable'= Enables updating metric consistent with Cisco; 'disable'= Disables updating metric consistent with Cisco;  (Enable/Disable updating metric consistent with Cisco)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    offset_list:
        description:
        - "Field offset_list"
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
            uuid:
                description:
                - "uuid of the object"
    route_map:
        description:
        - "Field route_map"
        required: False
        suboptions:
            map_cfg:
                description:
                - "Field map_cfg"
            uuid:
                description:
                - "uuid of the object"
    passive_interface_list:
        description:
        - "Field passive_interface_list"
        required: False
        suboptions:
            ethernet:
                description:
                - "Ethernet interface (Port number)"
            loopback:
                description:
                - "Loopback interface (Port number)"
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
    redistribute:
        description:
        - "Field redistribute"
        required: False
        suboptions:
            vip_list:
                description:
                - "Field vip_list"
            redist_list:
                description:
                - "Field redist_list"
            uuid:
                description:
                - "uuid of the object"
    route_cfg:
        description:
        - "Field route_cfg"
        required: False
        suboptions:
            route:
                description:
                - "Static route advertisement (debugging purpose) (IP prefix)"
    timers:
        description:
        - "Field timers"
        required: False
        suboptions:
            timers_cfg:
                description:
                - "Field timers_cfg"
    aggregate_address_cfg:
        description:
        - "Field aggregate_address_cfg"
        required: False
        suboptions:
            aggregate_address:
                description:
                - "Set aggregate RIP route announcement (Aggregate network)"
    default_information:
        description:
        - "'originate'= originate;  (Distribute default route)"
        required: False
    ripng_neighbor:
        description:
        - "Field ripng_neighbor"
        required: False
        suboptions:
            ripng_neighbor_cfg:
                description:
                - "Field ripng_neighbor_cfg"
    distribute_list:
        description:
        - "Field distribute_list"
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
            prefix:
                description:
                - "Field prefix"
            uuid:
                description:
                - "uuid of the object"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["aggregate_address_cfg","cisco_metric_behavior","default_information","default_metric","distribute_list","offset_list","passive_interface_list","recv_buffer_size","redistribute","ripng_neighbor","route_cfg","route_map","timers","uuid",]

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
        default_metric=dict(type='int',),
        recv_buffer_size=dict(type='int',),
        cisco_metric_behavior=dict(type='str',choices=['enable','disable']),
        uuid=dict(type='str',),
        offset_list=dict(type='dict',acl_cfg=dict(type='list',ve=dict(type='str',),loopback=dict(type='str',),metric=dict(type='int',),trunk=dict(type='str',),acl=dict(type='str',),offset_list_direction=dict(type='str',choices=['in','out']),ethernet=dict(type='str',)),uuid=dict(type='str',)),
        route_map=dict(type='dict',map_cfg=dict(type='list',map=dict(type='str',),ve=dict(type='str',),loopback=dict(type='str',),route_map_direction=dict(type='str',choices=['in','out']),trunk=dict(type='str',),ethernet=dict(type='str',)),uuid=dict(type='str',)),
        passive_interface_list=dict(type='list',ethernet=dict(type='str',),loopback=dict(type='str',),ve=dict(type='str',),trunk=dict(type='str',)),
        redistribute=dict(type='dict',vip_list=dict(type='list',vip_metric=dict(type='int',),vip_route_map=dict(type='str',),vip_type=dict(type='str',choices=['only-flagged','only-not-flagged'])),redist_list=dict(type='list',metric=dict(type='int',),route_map=dict(type='str',),ntype=dict(type='str',choices=['bgp','connected','floating-ip','ip-nat-list','ip-nat','isis','lw4o6','nat-map','nat64','ospf','static'])),uuid=dict(type='str',)),
        route_cfg=dict(type='list',route=dict(type='str',)),
        timers=dict(type='dict',timers_cfg=dict(type='dict',val_3=dict(type='int',),val_2=dict(type='int',),basic=dict(type='int',))),
        aggregate_address_cfg=dict(type='list',aggregate_address=dict(type='str',)),
        default_information=dict(type='str',choices=['originate']),
        ripng_neighbor=dict(type='dict',ripng_neighbor_cfg=dict(type='list',ethernet=dict(type='str',),neighbor_link_local_addr=dict(type='str',),ve=dict(type='str',),trunk=dict(type='str',),loopback=dict(type='str',))),
        distribute_list=dict(type='dict',acl_cfg=dict(type='list',acl_direction=dict(type='str',choices=['in','out']),ve=dict(type='str',),loopback=dict(type='str',),acl=dict(type='str',),trunk=dict(type='str',),ethernet=dict(type='str',)),prefix=dict(type='dict',uuid=dict(type='str',),prefix_cfg=dict(type='list',ve=dict(type='str',),loopback=dict(type='str',),prefix_list=dict(type='str',),trunk=dict(type='str',),prefix_list_direction=dict(type='str',choices=['in','out']),ethernet=dict(type='str',))),uuid=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ipv6/rip"

    f_dict = {}

    return url_base.format(**f_dict)

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
        for k, v in payload["rip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rip"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rip"][k] = v
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
    payload = build_json("rip", module)
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