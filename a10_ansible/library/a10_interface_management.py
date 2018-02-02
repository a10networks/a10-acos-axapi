#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_management
description:
    - None
short_description: Configures A10 interface.management
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
    access_list:
        description:
        - "Field access_list"
        required: False
        suboptions:
            acl_id:
                description:
                - "None"
            acl_name:
                description:
                - "None"
    duplexity:
        description:
        - "None"
        required: False
    speed:
        description:
        - "None"
        required: False
    flow_control:
        description:
        - "None"
        required: False
    broadcast_rate_limit:
        description:
        - "Field broadcast_rate_limit"
        required: False
        suboptions:
            bcast_rate_limit_enable:
                description:
                - "None"
            rate:
                description:
                - "None"
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            ipv4_address:
                description:
                - "None"
            ipv4_netmask:
                description:
                - "None"
            dhcp:
                description:
                - "None"
            control_apps_use_mgmt_port:
                description:
                - "None"
            default_gateway:
                description:
                - "None"
    secondary_ip:
        description:
        - "Field secondary_ip"
        required: False
        suboptions:
            secondary_ip:
                description:
                - "None"
            ipv4_address:
                description:
                - "None"
            ipv4_netmask:
                description:
                - "None"
            dhcp:
                description:
                - "None"
            control_apps_use_mgmt_port:
                description:
                - "None"
            default_gateway:
                description:
                - "None"
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            ipv6_addr:
                description:
                - "None"
            address_type:
                description:
                - "None"
            v6_acl_name:
                description:
                - "None"
            inbound:
                description:
                - "None"
            default_ipv6_gateway:
                description:
                - "None"
    action:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    lldp:
        description:
        - "Field lldp"
        required: False
        suboptions:
            enable_cfg:
                description:
                - "Field enable_cfg"
            notification_cfg:
                description:
                - "Field notification_cfg"
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
            uuid:
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
AVAILABLE_PROPERTIES = ["access_list","action","broadcast_rate_limit","duplexity","flow_control","ip","ipv6","lldp","secondary_ip","speed","uuid",]

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
        access_list=dict(type='dict',acl_id=dict(type='int',),acl_name=dict(type='str',)),
        duplexity=dict(type='str',choices=['Full','Half','auto']),
        speed=dict(type='str',choices=['10','100','1000','auto']),
        flow_control=dict(type='bool',),
        broadcast_rate_limit=dict(type='dict',bcast_rate_limit_enable=dict(type='bool',),rate=dict(type='int',)),
        ip=dict(type='dict',ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',),dhcp=dict(type='bool',),control_apps_use_mgmt_port=dict(type='bool',),default_gateway=dict(type='str',)),
        secondary_ip=dict(type='dict',secondary_ip=dict(type='bool',),ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',),dhcp=dict(type='bool',),control_apps_use_mgmt_port=dict(type='bool',),default_gateway=dict(type='str',)),
        ipv6=dict(type='dict',ipv6_addr=dict(type='str',),address_type=dict(type='str',choices=['link-local']),v6_acl_name=dict(type='str',),inbound=dict(type='bool',),default_ipv6_gateway=dict(type='str',)),
        action=dict(type='str',choices=['enable','disable']),
        uuid=dict(type='str',),
        lldp=dict(type='dict',enable_cfg=dict(type='dict',rt_enable=dict(type='bool',),rx=dict(type='bool',),tx=dict(type='bool',)),notification_cfg=dict(type='dict',notification=dict(type='bool',),notif_enable=dict(type='bool',)),tx_dot1_cfg=dict(type='dict',tx_dot1_tlvs=dict(type='bool',),link_aggregation=dict(type='bool',),vlan=dict(type='bool',)),tx_tlvs_cfg=dict(type='dict',tx_tlvs=dict(type='bool',),exclude=dict(type='bool',),management_address=dict(type='bool',),port_description=dict(type='bool',),system_capabilities=dict(type='bool',),system_description=dict(type='bool',),system_name=dict(type='bool',)),uuid=dict(type='str',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/management"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/management"
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("management", module)
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
    payload = build_json("management", module)
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