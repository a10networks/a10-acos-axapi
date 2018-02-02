#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_map_translation_domain
description:
    - None
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
    name:
        description:
        - "None"
        required: True
    description:
        description:
        - "None"
        required: False
    mtu:
        description:
        - "None"
        required: False
    tcp:
        description:
        - "Field tcp"
        required: False
        suboptions:
            mss_clamp:
                description:
                - "Field mss_clamp"
    uuid:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    health_check_gateway:
        description:
        - "Field health_check_gateway"
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
            ipv6_address_list:
                description:
                - "Field ipv6_address_list"
            withdraw_route:
                description:
                - "None"
            uuid:
                description:
                - "None"
    default_mapping_rule:
        description:
        - "Field default_mapping_rule"
        required: False
        suboptions:
            rule_ipv6_prefix:
                description:
                - "None"
            uuid:
                description:
                - "None"
    basic_mapping_rule:
        description:
        - "Field basic_mapping_rule"
        required: False
        suboptions:
            rule_ipv4_address_port_settings:
                description:
                - "None"
            ea_length:
                description:
                - "None"
            share_ratio:
                description:
                - "None"
            port_start:
                description:
                - "None"
            uuid:
                description:
                - "None"
            prefix_rule_list:
                description:
                - "Field prefix_rule_list"


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
        name=dict(type='str',required=True,),
        description=dict(type='str',),
        mtu=dict(type='int',),
        tcp=dict(type='dict',mss_clamp=dict(type='dict',mss_clamp_type=dict(type='str',choices=['fixed','none','subtract']),mss_value=dict(type='int',),mss_subtract=dict(type='int',),min=dict(type='int',))),
        uuid=dict(type='str',),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inbound_packet_received','inbound_frag_packet_received','inbound_addr_port_validation_failed','inbound_rev_lookup_failed','inbound_dest_unreachable','outbound_packet_received','outbound_frag_packet_received','outbound_addr_validation_failed','outbound_rev_lookup_failed','outbound_dest_unreachable','packet_mtu_exceeded','frag_icmp_sent','interface_not_configured','bmr_prefixrules_configured','helper_count','active_dhcpv6_leases','num_domains_configured'])),
        health_check_gateway=dict(type='dict',address_list=dict(type='list',ipv4_gateway=dict(type='str',)),ipv6_address_list=dict(type='list',ipv6_gateway=dict(type='str',)),withdraw_route=dict(type='str',choices=['all-link-failure','any-link-failure']),uuid=dict(type='str',)),
        default_mapping_rule=dict(type='dict',rule_ipv6_prefix=dict(type='str',),uuid=dict(type='str',)),
        basic_mapping_rule=dict(type='dict',rule_ipv4_address_port_settings=dict(type='str',choices=['prefix-addr','single-addr','shared-addr']),ea_length=dict(type='int',),share_ratio=dict(type='int',),port_start=dict(type='int',),uuid=dict(type='str',),prefix_rule_list=dict(type='list',name=dict(type='str',required=True,),rule_ipv6_prefix=dict(type='str',),rule_ipv4_prefix=dict(type='str',),ipv4_netmask=dict(type='str',),uuid=dict(type='str',),user_tag=dict(type='str',)))
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
    payload = build_json("domain", module)
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
    payload = build_json("domain", module)
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