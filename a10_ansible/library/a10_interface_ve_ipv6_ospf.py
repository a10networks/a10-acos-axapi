#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_ve_ipv6_ospf
description:
    - Open Shortest Path First for IPv6 (OSPFv3)
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
    partition:
        description:
        - Destination/target partition for object/command
    ve_ifnum:
        description:
        - Key to identify parent object
    uuid:
        description:
        - "uuid of the object"
        required: False
    bfd:
        description:
        - "Bidirectional Forwarding Detection (BFD)"
        required: False
    cost_cfg:
        description:
        - "Field cost_cfg"
        required: False
        suboptions:
            cost:
                description:
                - "Interface cost"
            instance_id:
                description:
                - "Specify the interface instance ID"
    priority_cfg:
        description:
        - "Field priority_cfg"
        required: False
        suboptions:
            priority:
                description:
                - "Router priority"
            instance_id:
                description:
                - "Specify the interface instance ID"
    hello_interval_cfg:
        description:
        - "Field hello_interval_cfg"
        required: False
        suboptions:
            hello_interval:
                description:
                - "Time between HELLO packets (Seconds)"
            instance_id:
                description:
                - "Specify the interface instance ID"
    mtu_ignore_cfg:
        description:
        - "Field mtu_ignore_cfg"
        required: False
        suboptions:
            mtu_ignore:
                description:
                - "Ignores the MTU in DBD packets"
            instance_id:
                description:
                - "Specify the interface instance ID"
    retransmit_interval_cfg:
        description:
        - "Field retransmit_interval_cfg"
        required: False
        suboptions:
            retransmit_interval:
                description:
                - "Time between retransmitting lost link state advertisements (Seconds)"
            instance_id:
                description:
                - "Specify the interface instance ID"
    disable:
        description:
        - "Disable BFD"
        required: False
    transmit_delay_cfg:
        description:
        - "Field transmit_delay_cfg"
        required: False
        suboptions:
            transmit_delay:
                description:
                - "Link state transmit delay (Seconds)"
            instance_id:
                description:
                - "Specify the interface instance ID"
    neighbor_cfg:
        description:
        - "Field neighbor_cfg"
        required: False
        suboptions:
            neighbor_priority:
                description:
                - "OSPF priority of non-broadcast neighbor"
            neighbor_poll_interval:
                description:
                - "OSPF dead-router polling interval (Seconds)"
            neig_inst:
                description:
                - "Specify the interface instance ID"
            neighbor:
                description:
                - "OSPFv3 neighbor (Neighbor IPv6 address)"
            neighbor_cost:
                description:
                - "OSPF cost for point-to-multipoint neighbor (metric)"
    network_list:
        description:
        - "Field network_list"
        required: False
        suboptions:
            broadcast_type:
                description:
                - "'broadcast'= Specify OSPF broadcast multi-access network; 'non-broadcast'= Specify OSPF NBMA network; 'point-to-point'= Specify OSPF point-to-point network; 'point-to-multipoint'= Specify OSPF point-to-multipoint network; "
            p2mp_nbma:
                description:
                - "Specify non-broadcast point-to-multipoint network"
            network_instance_id:
                description:
                - "Specify the interface instance ID"
    dead_interval_cfg:
        description:
        - "Field dead_interval_cfg"
        required: False
        suboptions:
            dead_interval:
                description:
                - "Interval after which a neighbor is declared dead (Seconds)"
            instance_id:
                description:
                - "Specify the interface instance ID"

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
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
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
   
    # Parent keys
    rv.update(dict(
        ve_ifnum=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ipv6/ospf"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ipv6/ospf"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

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
    payload = build_json("ospf", module)
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
    payload = build_json("ospf", module)
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
    payload = build_json("ospf", module)
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