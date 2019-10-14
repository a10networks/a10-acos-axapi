#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_map_translation_domain
description:
    - MAP Translation domain
short_description: Configures A10 cgnv6.map.translation.domain
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
    default_mapping_rule:
        description:
        - "Field default_mapping_rule"
        required: False
        suboptions:
            rule_ipv6_prefix:
                description:
                - "Rule IPv6 prefix"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    name:
        description:
        - "MAP-T domain name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    mtu:
        description:
        - "Domain MTU"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'inbound_packet_received'= Inbound IPv4 Packets Received; 'inbound_frag_packet_received'= Inbound IPv4 Fragment Packets Received; 'inbound_addr_port_validation_failed'= Inbound IPv4 Destination Address Port Validation Failed; 'inbound_rev_lookup_failed'= Inbound IPv4 Reverse Route Lookup Failed; 'inbound_dest_unreachable'= Inbound IPv6 Destination Address Unreachable; 'outbound_packet_received'= Outbound IPv6 Packets Received; 'outbound_frag_packet_received'= Outbound IPv6 Fragment Packets Received; 'outbound_addr_validation_failed'= Outbound IPv6 Source Address Validation Failed; 'outbound_rev_lookup_failed'= Outbound IPv6 Reverse Route Lookup Failed; 'outbound_dest_unreachable'= Outbound IPv4 Destination Address Unreachable; 'packet_mtu_exceeded'= Packet Exceeded MTU; 'frag_icmp_sent'= ICMP Packet Too Big Sent; 'interface_not_configured'= Interfaces not Configured Dropped; 'bmr_prefixrules_configured'= BMR prefix rules configured; 'helper_count'= Helper Count; 'active_dhcpv6_leases'= Active DHCPv6 leases; "
    tcp:
        description:
        - "Field tcp"
        required: False
        suboptions:
            mss_clamp:
                description:
                - "Field mss_clamp"
    health_check_gateway:
        description:
        - "Field health_check_gateway"
        required: False
        suboptions:
            ipv6_address_list:
                description:
                - "Field ipv6_address_list"
            address_list:
                description:
                - "Field address_list"
            withdraw_route:
                description:
                - "'all-link-failure'= Withdraw routes on health-check failure of all IPv4 gateways or all IPv6 gateways; 'any-link-failure'= Withdraw routes on health-check failure of any gateway (default); "
            uuid:
                description:
                - "uuid of the object"
    basic_mapping_rule:
        description:
        - "Field basic_mapping_rule"
        required: False
        suboptions:
            rule_ipv4_address_port_settings:
                description:
                - "'prefix-addr'= Each CE is assigned an IPv4 prefix; 'single-addr'= Each CE is assigned an IPv4 address; 'shared-addr'= Each CE is assigned a shared IPv4 address; "
            port_start:
                description:
                - "Starting Port, Must be Power of 2 value"
            uuid:
                description:
                - "uuid of the object"
            share_ratio:
                description:
                - "Port sharing ratio for each NAT IP. Must be Power of 2 value"
            prefix_rule_list:
                description:
                - "Field prefix_rule_list"
            ea_length:
                description:
                - "Length of Embedded Address (EA) bits"
    description:
        description:
        - "MAP-T domain description"
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
AVAILABLE_PROPERTIES = ["basic_mapping_rule","default_mapping_rule","description","health_check_gateway","mtu","name","sampling_enable","tcp","user_tag","uuid",]

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
        default_mapping_rule=dict(type='dict',rule_ipv6_prefix=dict(type='str',),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        name=dict(type='str',required=True,),
        user_tag=dict(type='str',),
        mtu=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inbound_packet_received','inbound_frag_packet_received','inbound_addr_port_validation_failed','inbound_rev_lookup_failed','inbound_dest_unreachable','outbound_packet_received','outbound_frag_packet_received','outbound_addr_validation_failed','outbound_rev_lookup_failed','outbound_dest_unreachable','packet_mtu_exceeded','frag_icmp_sent','interface_not_configured','bmr_prefixrules_configured','helper_count','active_dhcpv6_leases'])),
        tcp=dict(type='dict',mss_clamp=dict(type='dict',mss_subtract=dict(type='int',),mss_value=dict(type='int',),mss_clamp_type=dict(type='str',choices=['fixed','none','subtract']),min=dict(type='int',))),
        health_check_gateway=dict(type='dict',ipv6_address_list=dict(type='list',ipv6_gateway=dict(type='str',)),address_list=dict(type='list',ipv4_gateway=dict(type='str',)),withdraw_route=dict(type='str',choices=['all-link-failure','any-link-failure']),uuid=dict(type='str',)),
        basic_mapping_rule=dict(type='dict',rule_ipv4_address_port_settings=dict(type='str',choices=['prefix-addr','single-addr','shared-addr']),port_start=dict(type='int',),uuid=dict(type='str',),share_ratio=dict(type='int',),prefix_rule_list=dict(type='list',name=dict(type='str',required=True,),ipv4_netmask=dict(type='str',),rule_ipv4_prefix=dict(type='str',),user_tag=dict(type='str',),rule_ipv6_prefix=dict(type='str',),uuid=dict(type='str',)),ea_length=dict(type='int',)),
        description=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/map/translation/domain/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/map/translation/domain/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["domain"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["domain"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["domain"][k] = v
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
    payload = build_json("domain", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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