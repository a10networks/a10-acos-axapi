#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_ve_ipv6_ospf
description:
    - None
short_description: Configures A10 interface.ve.ipv6.ospf
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
    uuid:
        description:
        - "None"
        required: False
    bfd:
        description:
        - "None"
        required: False
    cost_cfg:
        description:
        - "Field cost_cfg"
        required: False
        suboptions:
            cost:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    priority_cfg:
        description:
        - "Field priority_cfg"
        required: False
        suboptions:
            priority:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    hello_interval_cfg:
        description:
        - "Field hello_interval_cfg"
        required: False
        suboptions:
            hello_interval:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    mtu_ignore_cfg:
        description:
        - "Field mtu_ignore_cfg"
        required: False
        suboptions:
            mtu_ignore:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    retransmit_interval_cfg:
        description:
        - "Field retransmit_interval_cfg"
        required: False
        suboptions:
            retransmit_interval:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    disable:
        description:
        - "None"
        required: False
    transmit_delay_cfg:
        description:
        - "Field transmit_delay_cfg"
        required: False
        suboptions:
            transmit_delay:
                description:
                - "None"
            instance_id:
                description:
                - "None"
    neighbor_cfg:
        description:
        - "Field neighbor_cfg"
        required: False
        suboptions:
            neighbor_priority:
                description:
                - "None"
            neighbor_poll_interval:
                description:
                - "None"
            neig_inst:
                description:
                - "None"
            neighbor:
                description:
                - "None"
            neighbor_cost:
                description:
                - "None"
    network_list:
        description:
        - "Field network_list"
        required: False
        suboptions:
            broadcast_type:
                description:
                - "None"
            p2mp_nbma:
                description:
                - "None"
            network_instance_id:
                description:
                - "None"
    dead_interval_cfg:
        description:
        - "Field dead_interval_cfg"
        required: False
        suboptions:
            dead_interval:
                description:
                - "None"
            instance_id:
                description:
                - "None"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["bfd","cost_cfg","dead_interval_cfg","disable","hello_interval_cfg","mtu_ignore_cfg","neighbor_cfg","network_list","priority_cfg","retransmit_interval_cfg","transmit_delay_cfg","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        uuid=dict(type='str',),
        bfd=dict(type='bool',),
        cost_cfg=dict(type='list',cost=dict(type='int',),instance_id=dict(type='int',)),
        priority_cfg=dict(type='list',priority=dict(type='int',),instance_id=dict(type='int',)),
        hello_interval_cfg=dict(type='list',hello_interval=dict(type='int',),instance_id=dict(type='int',)),
        mtu_ignore_cfg=dict(type='list',mtu_ignore=dict(type='bool',),instance_id=dict(type='int',)),
        retransmit_interval_cfg=dict(type='list',retransmit_interval=dict(type='int',),instance_id=dict(type='int',)),
        disable=dict(type='bool',),
        transmit_delay_cfg=dict(type='list',transmit_delay=dict(type='int',),instance_id=dict(type='int',)),
        neighbor_cfg=dict(type='list',neighbor_priority=dict(type='int',),neighbor_poll_interval=dict(type='int',),neig_inst=dict(type='int',),neighbor=dict(type='str',),neighbor_cost=dict(type='int',)),
        network_list=dict(type='list',broadcast_type=dict(type='str',choices=['broadcast','non-broadcast','point-to-point','point-to-multipoint']),p2mp_nbma=dict(type='bool',),network_instance_id=dict(type='int',)),
        dead_interval_cfg=dict(type='list',dead_interval=dict(type='int',),instance_id=dict(type='int',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ve/{ifnum}/ipv6/ospf"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ifnum}/ipv6/ospf"
    f_dict = {}

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
    payload = build_json("ospf", module)
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
    payload = build_json("ospf", module)
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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
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