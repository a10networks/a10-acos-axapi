#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_route_map
description:
    - Configure route-map
short_description: Configures A10 route-map
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
    set:
        description:
        - "Field set"
        required: False
        suboptions:
            extcommunity:
                description:
                - "Field extcommunity"
            origin:
                description:
                - "Field origin"
            originator_id:
                description:
                - "Field originator_id"
            weight:
                description:
                - "Field weight"
            level:
                description:
                - "Field level"
            ip:
                description:
                - "Field ip"
            metric:
                description:
                - "Field metric"
            as_path:
                description:
                - "Field as_path"
            comm_list:
                description:
                - "Field comm_list"
            atomic_aggregate:
                description:
                - "BGP atomic aggregate attribute"
            community:
                description:
                - "BGP community attribute"
            local_preference:
                description:
                - "Field local_preference"
            ddos:
                description:
                - "Field ddos"
            tag:
                description:
                - "Field tag"
            aggregator:
                description:
                - "Field aggregator"
            dampening_cfg:
                description:
                - "Field dampening_cfg"
            ipv6:
                description:
                - "Field ipv6"
            metric_type:
                description:
                - "Field metric_type"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    sequence:
        description:
        - "Sequence to insert to/delete from existing route-map entry"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    tag:
        description:
        - "Route map tag"
        required: True
    action:
        description:
        - "'permit'= Route map permits set operations; 'deny'= Route map denies set operations; "
        required: True
    match:
        description:
        - "Field match"
        required: False
        suboptions:
            extcommunity:
                description:
                - "Field extcommunity"
            origin:
                description:
                - "Field origin"
            group:
                description:
                - "Field group"
            uuid:
                description:
                - "uuid of the object"
            ip:
                description:
                - "Field ip"
            metric:
                description:
                - "Field metric"
            as_path:
                description:
                - "Field as_path"
            community:
                description:
                - "Field community"
            local_preference:
                description:
                - "Field local_preference"
            route_type:
                description:
                - "Field route_type"
            tag:
                description:
                - "Field tag"
            ipv6:
                description:
                - "Field ipv6"
            interface:
                description:
                - "Field interface"
            scaleout:
                description:
                - "Field scaleout"

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","match","sequence","set","tag","user_tag","uuid",]

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
        set=dict(type='dict',extcommunity=dict(type='dict',rt=dict(type='dict',value=dict(type='str',)),soo=dict(type='dict',value=dict(type='str',))),origin=dict(type='dict',egp=dict(type='bool',),incomplete=dict(type='bool',),igp=dict(type='bool',)),originator_id=dict(type='dict',originator_ip=dict(type='str',)),weight=dict(type='dict',weight_val=dict(type='int',)),level=dict(type='dict',value=dict(type='str',choices=['level-1','level-1-2','level-2'])),ip=dict(type='dict',next_hop=dict(type='dict',address=dict(type='str',))),metric=dict(type='dict',value=dict(type='str',)),as_path=dict(type='dict',num=dict(type='int',),num2=dict(type='int',),prepend=dict(type='str',)),comm_list=dict(type='dict',name=dict(type='str',),v_std=dict(type='int',),v_exp_delete=dict(type='bool',),v_exp=dict(type='int',),name_delete=dict(type='bool',),delete=dict(type='bool',)),atomic_aggregate=dict(type='bool',),community=dict(type='str',),local_preference=dict(type='dict',val=dict(type='int',)),ddos=dict(type='dict',class_list_name=dict(type='str',),class_list_cid=dict(type='int',),zone=dict(type='str',)),tag=dict(type='dict',value=dict(type='int',)),aggregator=dict(type='dict',aggregator_as=dict(type='dict',ip=dict(type='str',),asn=dict(type='int',))),dampening_cfg=dict(type='dict',dampening_max_supress=dict(type='int',),dampening=dict(type='bool',),dampening_penalty=dict(type='int',),dampening_half_time=dict(type='int',),dampening_supress=dict(type='int',),dampening_reuse=dict(type='int',)),ipv6=dict(type='dict',next_hop_1=dict(type='dict',local=dict(type='dict',address=dict(type='str',)),address=dict(type='str',))),metric_type=dict(type='dict',value=dict(type='str',choices=['external','internal','type-1','type-2'])),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        sequence=dict(type='int',required=True,),
        user_tag=dict(type='str',),
        tag=dict(type='str',required=True,),
        action=dict(type='str',required=True,choices=['permit','deny']),
        match=dict(type='dict',extcommunity=dict(type='dict',extcommunity_l_name=dict(type='dict',exact_match=dict(type='bool',),name=dict(type='str',))),origin=dict(type='dict',egp=dict(type='bool',),incomplete=dict(type='bool',),igp=dict(type='bool',)),group=dict(type='dict',group_id=dict(type='int',),ha_state=dict(type='str',choices=['active','standby'])),uuid=dict(type='str',),ip=dict(type='dict',peer=dict(type='dict',acl1=dict(type='int',),acl2=dict(type='int',),name=dict(type='str',)),next_hop=dict(type='dict',acl1=dict(type='int',),acl2=dict(type='int',),name=dict(type='str',),prefix_list_1=dict(type='dict',name=dict(type='str',))),address=dict(type='dict',acl1=dict(type='int',),acl2=dict(type='int',),prefix_list=dict(type='dict',name=dict(type='str',)),name=dict(type='str',))),metric=dict(type='dict',value=dict(type='int',)),as_path=dict(type='dict',name=dict(type='str',)),community=dict(type='dict',name_cfg=dict(type='dict',exact_match=dict(type='bool',),name=dict(type='str',))),local_preference=dict(type='dict',val=dict(type='int',)),route_type=dict(type='dict',external=dict(type='dict',value=dict(type='str',choices=['type-1','type-2']))),tag=dict(type='dict',value=dict(type='int',)),ipv6=dict(type='dict',next_hop_1=dict(type='dict',prefix_list_name=dict(type='str',),v6_addr=dict(type='str',),next_hop_acl_name=dict(type='str',)),peer_1=dict(type='dict',acl1=dict(type='int',),acl2=dict(type='int',),name=dict(type='str',)),address_1=dict(type='dict',name=dict(type='str',),prefix_list_2=dict(type='dict',name=dict(type='str',)))),interface=dict(type='dict',tunnel=dict(type='str',),ethernet=dict(type='str',),loopback=dict(type='int',),ve=dict(type='int',),trunk=dict(type='int',)),scaleout=dict(type='dict',cluster_id=dict(type='int',),operational_state=dict(type='str',choices=['up','down'])))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/route-map/{tag}+{action}+{sequence}"

    f_dict = {}
    f_dict["tag"] = ""
    f_dict["action"] = ""
    f_dict["sequence"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/route-map/{tag}+{action}+{sequence}"

    f_dict = {}
    f_dict["tag"] = module.params["tag"]
    f_dict["action"] = module.params["action"]
    f_dict["sequence"] = module.params["sequence"]

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
        return False

def create(module, result):
    payload = build_json("route-map", module)
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
    payload = build_json("route-map", module)
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
    payload = build_json("route-map", module)
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