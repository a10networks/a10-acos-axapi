#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_management
description:
    - Management interface
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
    lldp:
        description:
        - "Field lldp"
        required: False
        suboptions:
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
            notification_cfg:
                description:
                - "Field notification_cfg"
            enable_cfg:
                description:
                - "Field enable_cfg"
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
            uuid:
                description:
                - "uuid of the object"
    flow_control:
        description:
        - "Enable 802.3x flow control on full duplex port"
        required: False
    broadcast_rate_limit:
        description:
        - "Field broadcast_rate_limit"
        required: False
        suboptions:
            rate:
                description:
                - "packets per second. Default is 500. (packets per second. Please specify an even number. Default is 500)"
            bcast_rate_limit_enable:
                description:
                - "Rate limit the l2 broadcast packet on mgmt port"
    uuid:
        description:
        - "uuid of the object"
        required: False
    duplexity:
        description:
        - "'Full'= Full; 'Half'= Half; 'auto'= Auto; "
        required: False
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            dhcp:
                description:
                - "Use DHCP to configure IP address"
            ipv4_address:
                description:
                - "IP address"
            control_apps_use_mgmt_port:
                description:
                - "Control applications use management port"
            default_gateway:
                description:
                - "Set default gateway (Default gateway address)"
            ipv4_netmask:
                description:
                - "IP subnet mask"
    access_list:
        description:
        - "Field access_list"
        required: False
        suboptions:
            acl_name:
                description:
                - "Apply an access list (Named Access List)"
            acl_id:
                description:
                - "ACL id"
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
            address_type:
                description:
                - "'link-local'= Configure an IPv6 link local address; "
            default_ipv6_gateway:
                description:
                - "Set default gateway (Default gateway address)"
            ipv6_addr:
                description:
                - "Set the IPv6 address of an interface"
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
    action:
        description:
        - "'enable'= Enable Management Port; 'disable'= Disable Management Port; "
        required: False
    speed:
        description:
        - "'10'= 10 Mbs/sec; '100'= 100 Mbs/sec; '1000'= 1 Gb/sec; 'auto'= Auto Negotiate Speed;  (Interface Speed)"
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
AVAILABLE_PROPERTIES = ["access_list","action","broadcast_rate_limit","duplexity","flow_control","ip","ipv6","lldp","speed","uuid",]

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
        lldp=dict(type='dict',tx_dot1_cfg=dict(type='dict',link_aggregation=dict(type='bool',),vlan=dict(type='bool',),tx_dot1_tlvs=dict(type='bool',)),notification_cfg=dict(type='dict',notification=dict(type='bool',),notif_enable=dict(type='bool',)),enable_cfg=dict(type='dict',rx=dict(type='bool',),tx=dict(type='bool',),rt_enable=dict(type='bool',)),tx_tlvs_cfg=dict(type='dict',system_capabilities=dict(type='bool',),system_description=dict(type='bool',),management_address=dict(type='bool',),tx_tlvs=dict(type='bool',),exclude=dict(type='bool',),port_description=dict(type='bool',),system_name=dict(type='bool',)),uuid=dict(type='str',)),
        flow_control=dict(type='bool',),
        broadcast_rate_limit=dict(type='dict',rate=dict(type='int',),bcast_rate_limit_enable=dict(type='bool',)),
        uuid=dict(type='str',),
        duplexity=dict(type='str',choices=['Full','Half','auto']),
        ip=dict(type='dict',dhcp=dict(type='bool',),ipv4_address=dict(type='str',),control_apps_use_mgmt_port=dict(type='bool',),default_gateway=dict(type='str',),ipv4_netmask=dict(type='str',)),
        access_list=dict(type='dict',acl_name=dict(type='str',),acl_id=dict(type='int',)),
        ipv6=dict(type='dict',inbound=dict(type='bool',),address_type=dict(type='str',choices=['link-local']),default_ipv6_gateway=dict(type='str',),ipv6_addr=dict(type='str',),v6_acl_name=dict(type='str',)),
        action=dict(type='str',choices=['enable','disable']),
        speed=dict(type='str',choices=['10','100','1000','auto'])
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
        for k, v in payload["management"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["management"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["management"][k] = v
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
    payload = build_json("management", module)
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