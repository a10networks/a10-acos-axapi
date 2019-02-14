#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vrrp_a_vrid
description:
    - Specify VRRP-A vrid
short_description: Configures A10 vrrp-a.vrid
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
    blade_parameters:
        description:
        - "Field blade_parameters"
        required: False
        suboptions:
            priority:
                description:
                - "VRRP-A priorty (Priority, default is 150)"
            fail_over_policy_template:
                description:
                - "Apply a fail over policy template (VRRP-A fail over policy template name)"
            uuid:
                description:
                - "uuid of the object"
            tracking_options:
                description:
                - "Field tracking_options"
    uuid:
        description:
        - "uuid of the object"
        required: False
    vrid_val:
        description:
        - "Specify ha VRRP-A vrid"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    preempt_mode:
        description:
        - "Field preempt_mode"
        required: False
        suboptions:
            threshold:
                description:
                - "preemption threshold (preemption threshhold (0-255), default 0)"
            disable:
                description:
                - "disable preemption"
    floating_ip:
        description:
        - "Field floating_ip"
        required: False
        suboptions:
            ipv6_address_part_cfg:
                description:
                - "Field ipv6_address_part_cfg"
            ip_address_cfg:
                description:
                - "Field ip_address_cfg"
            ip_address_part_cfg:
                description:
                - "Field ip_address_part_cfg"
            ipv6_address_cfg:
                description:
                - "Field ipv6_address_cfg"
    follow:
        description:
        - "Field follow"
        required: False
        suboptions:
            vrid_lead:
                description:
                - "Define a VRRP-A VRID leader"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["blade_parameters","floating_ip","follow","preempt_mode","user_tag","uuid","vrid_val",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        blade_parameters=dict(type='dict',priority=dict(type='int',),fail_over_policy_template=dict(type='str',),uuid=dict(type='str',),tracking_options=dict(type='dict',vlan_cfg=dict(type='list',vlan=dict(type='int',),timeout=dict(type='int',),priority_cost=dict(type='int',)),uuid=dict(type='str',),route=dict(type='dict',ipv6_destination_cfg=dict(type='list',ipv6_destination=dict(type='str',),distance=dict(type='int',),gatewayv6=dict(type='str',),protocol=dict(type='str',choices=['any','static','dynamic']),priority_cost=dict(type='int',)),ip_destination_cfg=dict(type='list',distance=dict(type='int',),protocol=dict(type='str',choices=['any','static','dynamic']),mask=dict(type='str',),priority_cost=dict(type='int',),ip_destination=dict(type='str',),gateway=dict(type='str',))),bgp=dict(type='dict',bgp_ipv4_address_cfg=dict(type='list',bgp_ipv4_address=dict(type='str',),priority_cost=dict(type='int',)),bgp_ipv6_address_cfg=dict(type='list',bgp_ipv6_address=dict(type='str',),priority_cost=dict(type='int',))),interface=dict(type='list',ethernet=dict(type='str',),priority_cost=dict(type='int',)),gateway=dict(type='dict',ipv4_gateway_list=dict(type='list',uuid=dict(type='str',),ip_address=dict(type='str',required=True,),priority_cost=dict(type='int',)),ipv6_gateway_list=dict(type='list',ipv6_address=dict(type='str',required=True,),uuid=dict(type='str',),priority_cost=dict(type='int',))),trunk_cfg=dict(type='list',priority_cost=dict(type='int',),trunk=dict(type='int',),per_port_pri=dict(type='int',)))),
        uuid=dict(type='str',),
        vrid_val=dict(type='int',required=True,),
        user_tag=dict(type='str',),
        preempt_mode=dict(type='dict',threshold=dict(type='int',),disable=dict(type='bool',)),
        floating_ip=dict(type='dict',ipv6_address_part_cfg=dict(type='list',ethernet=dict(type='str',),ipv6_address_partition=dict(type='str',),ve=dict(type='int',),trunk=dict(type='int',)),ip_address_cfg=dict(type='list',ip_address=dict(type='str',)),ip_address_part_cfg=dict(type='list',ip_address_partition=dict(type='str',)),ipv6_address_cfg=dict(type='list',ipv6_address=dict(type='str',),ethernet=dict(type='str',),ve=dict(type='int',),trunk=dict(type='int',))),
        follow=dict(type='dict',vrid_lead=dict(type='str',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vrrp-a/vrid/{vrid-val}"
    f_dict = {}
    f_dict["vrid-val"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vrrp-a/vrid/{vrid-val}"
    f_dict = {}
    f_dict["vrid-val"] = module.params["vrid-val"]

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
    payload = build_json("vrid", module)
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
    payload = build_json("vrid", module)
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