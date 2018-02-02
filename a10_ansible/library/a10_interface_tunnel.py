#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_tunnel
description:
    - None
short_description: Configures A10 interface.tunnel
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
    ifnum:
        description:
        - "None"
        required: True
    name:
        description:
        - "None"
        required: False
    mtu:
        description:
        - "None"
        required: False
    action:
        description:
        - "None"
        required: False
    speed:
        description:
        - "None"
        required: False
    load_interval:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            address:
                description:
                - "Field address"
            generate_membership_query:
                description:
                - "None"
            generate_membership_query_val:
                description:
                - "None"
            max_resp_time:
                description:
                - "None"
            uuid:
                description:
                - "None"
            ospf:
                description:
                - "Field ospf"
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            address_cfg:
                description:
                - "Field address_cfg"
            ipv6_enable:
                description:
                - "None"
            uuid:
                description:
                - "None"
            router:
                description:
                - "Field router"
            ospf:
                description:
                - "Field ospf"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","ifnum","ip","ipv6","load_interval","mtu","name","speed","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory
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
        ifnum=dict(type='int',required=True,),
        name=dict(type='str',),
        mtu=dict(type='int',),
        action=dict(type='str',choices=['enable','disable']),
        speed=dict(type='int',),
        load_interval=dict(type='int',),
        uuid=dict(type='str',),
        user_tag=dict(type='str',),
        ip=dict(type='dict',address=dict(type='dict',ip_cfg=dict(type='list',ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',))),generate_membership_query=dict(type='bool',),generate_membership_query_val=dict(type='int',),max_resp_time=dict(type='int',),uuid=dict(type='str',),ospf=dict(type='dict',ospf_global=dict(type='dict',authentication_cfg=dict(type='dict',authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null'])),authentication_key=dict(type='str',),bfd_cfg=dict(type='dict',bfd=dict(type='bool',),disable=dict(type='bool',)),cost=dict(type='int',),database_filter_cfg=dict(type='dict',database_filter=dict(type='str',choices=['all']),out=dict(type='bool',)),dead_interval=dict(type='int',),disable=dict(type='str',choices=['all']),hello_interval=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5=dict(type='dict',md5_value=dict(type='str',),encrypted=dict(type='str',))),mtu=dict(type='int',),mtu_ignore=dict(type='bool',),network=dict(type='dict',broadcast=dict(type='bool',),non_broadcast=dict(type='bool',),point_to_point=dict(type='bool',),point_to_multipoint=dict(type='bool',),p2mp_nbma=dict(type='bool',)),priority=dict(type='int',),retransmit_interval=dict(type='int',),transmit_delay=dict(type='int',),uuid=dict(type='str',)),ospf_ip_list=dict(type='list',ip_addr=dict(type='str',required=True,),authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null']),authentication_key=dict(type='str',),cost=dict(type='int',),database_filter=dict(type='str',choices=['all']),out=dict(type='bool',),dead_interval=dict(type='int',),hello_interval=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5_value=dict(type='str',),encrypted=dict(type='str',)),mtu_ignore=dict(type='bool',),priority=dict(type='int',),retransmit_interval=dict(type='int',),transmit_delay=dict(type='int',),uuid=dict(type='str',)))),
        ipv6=dict(type='dict',address_cfg=dict(type='list',ipv6_addr=dict(type='str',),address_type=dict(type='str',choices=['anycast','link-local'])),ipv6_enable=dict(type='bool',),uuid=dict(type='str',),router=dict(type='dict',ripng=dict(type='dict',rip=dict(type='bool',),uuid=dict(type='str',)),ospf=dict(type='dict',area_list=dict(type='list',area_id_num=dict(type='int',),area_id_addr=dict(type='str',),tag=dict(type='str',),instance_id=dict(type='int',)),uuid=dict(type='str',))),ospf=dict(type='dict',network_list=dict(type='list',broadcast_type=dict(type='str',choices=['broadcast','non-broadcast','point-to-point','point-to-multipoint']),p2mp_nbma=dict(type='bool',),network_instance_id=dict(type='int',)),bfd=dict(type='bool',),disable=dict(type='bool',),cost_cfg=dict(type='list',cost=dict(type='int',),instance_id=dict(type='int',)),dead_interval_cfg=dict(type='list',dead_interval=dict(type='int',),instance_id=dict(type='int',)),hello_interval_cfg=dict(type='list',hello_interval=dict(type='int',),instance_id=dict(type='int',)),mtu_ignore_cfg=dict(type='list',mtu_ignore=dict(type='bool',),instance_id=dict(type='int',)),neighbor_cfg=dict(type='list',neighbor=dict(type='str',),neig_inst=dict(type='int',),neighbor_cost=dict(type='int',),neighbor_poll_interval=dict(type='int',),neighbor_priority=dict(type='int',)),priority_cfg=dict(type='list',priority=dict(type='int',),instance_id=dict(type='int',)),retransmit_interval_cfg=dict(type='list',retransmit_interval=dict(type='int',),instance_id=dict(type='int',)),transmit_delay_cfg=dict(type='list',transmit_delay=dict(type='int',),instance_id=dict(type='int',)),uuid=dict(type='str',)))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/tunnel/{ifnum}"
    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/tunnel/{ifnum}"
    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("tunnel", module)
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
    payload = build_json("tunnel", module)
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

    valid = True

    if state == 'present':
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