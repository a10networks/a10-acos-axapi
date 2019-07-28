#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_axdebug_filter_config
description:
    - Global debug filter
short_description: Configures A10 axdebug.filter-config
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
    arp:
        description:
        - "ARP"
        required: False
    ip:
        description:
        - "IP"
        required: False
    offset:
        description:
        - "byte offset"
        required: False
    number:
        description:
        - "Specify filter id"
        required: True
    tcp:
        description:
        - "Field tcp"
        required: False
    l3_proto:
        description:
        - "Layer 3 protocol"
        required: False
    ipv4_address:
        description:
        - "ip address"
        required: False
    port:
        description:
        - "port number"
        required: False
    port_num_min:
        description:
        - "min port number"
        required: False
    oper_range:
        description:
        - "'gt'= greater than; 'gte'= greater than or equal to; 'se'= smaller than or equal to; 'st'= smaller than; 'eq'= equal to; "
        required: False
    ipv6_adddress:
        description:
        - "ipv6 address"
        required: False
    WORD:
        description:
        - "WORD to compare"
        required: False
    comp_hex:
        description:
        - "value to compare"
        required: False
    proto:
        description:
        - "ip protocol number"
        required: False
    dst:
        description:
        - "Destination"
        required: False
    hex:
        description:
        - "Define hex value"
        required: False
    integer_comp:
        description:
        - "value to compare"
        required: False
    port_num_max:
        description:
        - "max port number"
        required: False
    exit:
        description:
        - "Exit from axdebug mode"
        required: False
    ipv6:
        description:
        - "IPV6"
        required: False
    length:
        description:
        - "byte length"
        required: False
    udp:
        description:
        - "Field udp"
        required: False
    neighbor:
        description:
        - "IPv6 Neighbor/Router"
        required: False
    port_num:
        description:
        - "Port number"
        required: False
    max_hex:
        description:
        - "max value"
        required: False
    mac:
        description:
        - "mac address"
        required: False
    min_hex:
        description:
        - "min value"
        required: False
    WORD1:
        description:
        - "WORD min value"
        required: False
    WORD2:
        description:
        - "WORD max value"
        required: False
    integer_max:
        description:
        - "max value"
        required: False
    integer:
        description:
        - "Define decimal value"
        required: False
    icmp:
        description:
        - "Field icmp"
        required: False
    src:
        description:
        - "Source"
        required: False
    mac_addr:
        description:
        - "mac address"
        required: False
    ipv4_netmask:
        description:
        - "IP subnet mask"
        required: False
    icmpv6:
        description:
        - "Field icmpv6"
        required: False
    range:
        description:
        - "select a range"
        required: False
    integer_min:
        description:
        - "min value"
        required: False
    prot_num:
        description:
        - "protocol number"
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
AVAILABLE_PROPERTIES = ["arp","comp_hex","dst","exit","hex","icmp","icmpv6","integer","integer_comp","integer_max","integer_min","ip","ipv4_address","ipv4_netmask","ipv6","ipv6_adddress","l3_proto","length","mac","mac_addr","max_hex","min_hex","neighbor","number","offset","oper_range","port","port_num","port_num_max","port_num_min","prot_num","proto","range","src","tcp","udp","WORD","WORD1","WORD2",]

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
        arp=dict(type='bool',),
        ip=dict(type='bool',),
        offset=dict(type='int',),
        number=dict(type='int',required=True,),
        tcp=dict(type='bool',),
        l3_proto=dict(type='bool',),
        ipv4_address=dict(type='str',),
        port=dict(type='bool',),
        port_num_min=dict(type='int',),
        oper_range=dict(type='str',choices=['gt','gte','se','st','eq']),
        ipv6_adddress=dict(type='str',),
        WORD=dict(type='str',),
        comp_hex=dict(type='str',),
        proto=dict(type='bool',),
        dst=dict(type='bool',),
        hex=dict(type='bool',),
        integer_comp=dict(type='int',),
        port_num_max=dict(type='int',),
        exit=dict(type='bool',),
        ipv6=dict(type='bool',),
        length=dict(type='int',),
        udp=dict(type='bool',),
        neighbor=dict(type='bool',),
        port_num=dict(type='int',),
        max_hex=dict(type='str',),
        mac=dict(type='bool',),
        min_hex=dict(type='str',),
        WORD1=dict(type='str',),
        WORD2=dict(type='str',),
        integer_max=dict(type='int',),
        integer=dict(type='bool',),
        icmp=dict(type='bool',),
        src=dict(type='bool',),
        mac_addr=dict(type='str',),
        ipv4_netmask=dict(type='str',),
        icmpv6=dict(type='bool',),
        range=dict(type='bool',),
        integer_min=dict(type='int',),
        prot_num=dict(type='int',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/axdebug/filter-config"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/axdebug/filter-config"

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
    payload = build_json("filter-config", module)
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
    payload = build_json("filter-config", module)
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
    payload = build_json("filter-config", module)
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