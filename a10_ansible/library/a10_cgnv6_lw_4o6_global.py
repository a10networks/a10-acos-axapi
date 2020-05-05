#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_lw_4o6_global
description:
    - Configure LW-4over6 parameters
short_description: Configures A10 cgnv6.lw.4o6.global
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    no_forward_match:
        description:
        - "Field no_forward_match"
        required: False
        suboptions:
            send_icmpv6:
                description:
                - "Send ICMPv6 Type 1 Code 5"
    nat_prefix_list:
        description:
        - "Configure LW-4over6 NAT Prefix List (LW-4over6 NAT Prefix Class-list)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    hairpinning:
        description:
        - "'filter-all'= Disable all Hairpinning; 'filter-none'= Allow all Hairpinning (default); 'filter-self-ip'= Block Hairpinning to same IP; 'filter-self-ip-port'= Block hairpinning to same IP and Port combination; "
        required: False
    inside_src_access_list:
        description:
        - "Access List for inside IPv4 addresses (ACL ID)"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'entry_count'= Total Entries Configured; 'self_hairpinning_drop'= Self-Hairpinning Drops; 'all_hairpinning_drop'= All Hairpinning Drops; 'no_match_icmpv6_sent'= No-Forward-Match ICMPv6 Sent; 'no_match_icmp_sent'= No-Reverse-Match ICMP Sent; 'icmp_inbound_drop'= Inbound ICMP Drops; 'fwd_lookup_failed'= Forward Route Lookup Failed; 'rev_lookup_failed'= Reverse Route Lookup Failed; 'interface_not_configured'= LW-4over6 Interfaces not Configured Drops; 'no_binding_table_matches_fwd'= No Forward Binding Table Entry Match Drops; 'no_binding_table_matches_rev'= No Reverse Binding Table Entry Match Drops; 'session_count'= LW-4over6 Session Count; 'system_address_drop'= LW-4over6 System Address Drops; "
    icmp_inbound:
        description:
        - "'drop'= Drop Inbound ICMP packets; 'handle'= Handle Inbound ICMP packets(default); "
        required: False
    use_binding_table:
        description:
        - "Bind LW-4over6 binding table for use (LW-4over6 Binding Table Name)"
        required: False
    no_reverse_match:
        description:
        - "Field no_reverse_match"
        required: False
        suboptions:
            send_icmp:
                description:
                - "Send ICMP Type 3 Code 1"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            interface_not_configured:
                description:
                - "LW-4over6 Interfaces not Configured Drops"
            no_match_icmp_sent:
                description:
                - "No-Reverse-Match ICMP Sent"
            no_binding_table_matches_rev:
                description:
                - "No Reverse Binding Table Entry Match Drops"
            rev_lookup_failed:
                description:
                - "Reverse Route Lookup Failed"
            self_hairpinning_drop:
                description:
                - "Self-Hairpinning Drops"
            entry_count:
                description:
                - "Total Entries Configured"
            all_hairpinning_drop:
                description:
                - "All Hairpinning Drops"
            icmp_inbound_drop:
                description:
                - "Inbound ICMP Drops"
            fwd_lookup_failed:
                description:
                - "Forward Route Lookup Failed"
            no_binding_table_matches_fwd:
                description:
                - "No Forward Binding Table Entry Match Drops"
            no_match_icmpv6_sent:
                description:
                - "No-Forward-Match ICMPv6 Sent"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["hairpinning","icmp_inbound","inside_src_access_list","nat_prefix_list","no_forward_match","no_reverse_match","sampling_enable","stats","use_binding_table","uuid",]

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
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        no_forward_match=dict(type='dict',send_icmpv6=dict(type='bool',)),
        nat_prefix_list=dict(type='str',),
        uuid=dict(type='str',),
        hairpinning=dict(type='str',choices=['filter-all','filter-none','filter-self-ip','filter-self-ip-port']),
        inside_src_access_list=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','entry_count','self_hairpinning_drop','all_hairpinning_drop','no_match_icmpv6_sent','no_match_icmp_sent','icmp_inbound_drop','fwd_lookup_failed','rev_lookup_failed','interface_not_configured','no_binding_table_matches_fwd','no_binding_table_matches_rev','session_count','system_address_drop'])),
        icmp_inbound=dict(type='str',choices=['drop','handle']),
        use_binding_table=dict(type='str',),
        no_reverse_match=dict(type='dict',send_icmp=dict(type='bool',)),
        stats=dict(type='dict',interface_not_configured=dict(type='str',),no_match_icmp_sent=dict(type='str',),no_binding_table_matches_rev=dict(type='str',),rev_lookup_failed=dict(type='str',),self_hairpinning_drop=dict(type='str',),entry_count=dict(type='str',),all_hairpinning_drop=dict(type='str',),icmp_inbound_drop=dict(type='str',),fwd_lookup_failed=dict(type='str',),no_binding_table_matches_fwd=dict(type='str',),no_match_icmpv6_sent=dict(type='str',))
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lw-4o6/global"

    f_dict = {}

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lw-4o6/global"

    f_dict = {}

    return url_base.format(**f_dict)

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["global"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["global"][k] = v
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
    payload = build_json("global", module)
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

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
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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