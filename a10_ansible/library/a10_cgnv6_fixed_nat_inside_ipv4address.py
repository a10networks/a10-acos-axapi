#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_fixed_nat_inside_ipv4address
description:
    - Configure Fixed NAT
short_description: Configures A10 cgnv6.fixed.nat.inside.ipv4address
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
        - "Inside User Partition (Partition Name)"
        required: True
    inside_netmask:
        description:
        - "IPv4 Netmask"
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    nat_end_address:
        description:
        - "IPv4 End NAT Address"
        required: False
    vrid:
        description:
        - "VRRP-A vrid (Specify ha VRRP-A vrid)"
        required: False
    ports_per_user:
        description:
        - "Configure Ports per Inside User (ports-per-user)"
        required: False
    session_quota:
        description:
        - "Configure per user quota on sessions"
        required: False
    method:
        description:
        - "'use-all-nat-ips'= Use all the NAT IP addresses configured; 'use-least-nat-ips'= Use the least number of NAT IP addresses required (default); "
        required: False
    inside_start_address:
        description:
        - "IPv4 Inside User Start Address"
        required: True
    dest_rule_list:
        description:
        - "Bind destination based Rule-List (Fixed NAT Rule-List Name)"
        required: False
    nat_start_address:
        description:
        - "Start NAT Address"
        required: False
    nat_ip_list:
        description:
        - "Name of IP List used to specify NAT addresses"
        required: False
    offset:
        description:
        - "Field offset"
        required: False
        suboptions:
            numeric_offset:
                description:
                - "Configure a numeric offset to the first NAT IP address"
            random:
                description:
                - "Randomly choose the first NAT IP address"
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table (Default= off)"
        required: False
    inside_end_address:
        description:
        - "IPv4 Inside User End Address"
        required: True
    usable_nat_ports:
        description:
        - "Field usable_nat_ports"
        required: False
        suboptions:
            usable_start_port:
                description:
                - "Start Port of Usable NAT Ports"
            usable_end_port:
                description:
                - "End Port of Usable NAT Ports"
    nat_netmask:
        description:
        - "NAT Addresses IP Netmask"
        required: False
    dynamic_pool_size:
        description:
        - "Configure size of Dynamic pool (Default= 0)"
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
AVAILABLE_PROPERTIES = ["dest_rule_list","dynamic_pool_size","inside_end_address","inside_netmask","inside_start_address","method","nat_end_address","nat_ip_list","nat_netmask","nat_start_address","offset","partition","ports_per_user","respond_to_user_mac","session_quota","usable_nat_ports","uuid","vrid",]

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
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        partition=dict(type='str',required=True,),
        inside_netmask=dict(type='str',required=True,),
        uuid=dict(type='str',),
        nat_end_address=dict(type='str',),
        vrid=dict(type='int',),
        ports_per_user=dict(type='int',),
        session_quota=dict(type='int',),
        method=dict(type='str',choices=['use-all-nat-ips','use-least-nat-ips']),
        inside_start_address=dict(type='str',required=True,),
        dest_rule_list=dict(type='str',),
        nat_start_address=dict(type='str',),
        nat_ip_list=dict(type='str',),
        offset=dict(type='dict',numeric_offset=dict(type='int',),random=dict(type='bool',)),
        respond_to_user_mac=dict(type='bool',),
        inside_end_address=dict(type='str',required=True,),
        usable_nat_ports=dict(type='dict',usable_start_port=dict(type='int',),usable_end_port=dict(type='int',)),
        nat_netmask=dict(type='str',),
        dynamic_pool_size=dict(type='int',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv4address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"
    f_dict = {}
    f_dict["inside-start-address"] = ""
    f_dict["inside-end-address"] = ""
    f_dict["inside-netmask"] = ""
    f_dict["partition"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv4address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"
    f_dict = {}
    f_dict["inside-start-address"] = module.params["inside-start-address"]
    f_dict["inside-end-address"] = module.params["inside-end-address"]
    f_dict["inside-netmask"] = module.params["inside-netmask"]
    f_dict["partition"] = module.params["partition"]

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
    payload = build_json("ipv4address", module)
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
    payload = build_json("ipv4address", module)
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