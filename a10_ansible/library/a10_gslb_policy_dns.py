#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_policy_dns
description:
    - DNS related policy
short_description: Configures A10 gslb.policy.dns
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
    policy_name:
        description:
        - Key to identify parent object
    server_mode_only:
        description:
        - "Only run GSLB as DNS server mode"
        required: False
    external_soa:
        description:
        - "Return DNS response with external SOA Record"
        required: False
    server_sec:
        description:
        - "Provide DNSSEC support"
        required: False
    sticky_ipv6_mask:
        description:
        - "Specify IPv6 mask length, default is 128"
        required: False
    sticky:
        description:
        - "Make DNS Record sticky for certain time"
        required: False
    delegation:
        description:
        - "Zone Delegation"
        required: False
    active_only_fail_safe:
        description:
        - "Continue if no candidate"
        required: False
    cname_detect:
        description:
        - "Apply GSLB for DNS Server response when service is Canonical Name (CNAME)"
        required: False
    ttl:
        description:
        - "Specify the TTL value contained in DNS record (TTL value, unit= second, default is 10)"
        required: False
    dynamic_preference:
        description:
        - "Make dynamically change the preference"
        required: False
    use_server_ttl:
        description:
        - "Use DNS Server Response TTL value in GSLB Proxy mode"
        required: False
    server_ptr:
        description:
        - "Provide PTR Records"
        required: False
    selected_only:
        description:
        - "Only keep selected servers"
        required: False
    ip_replace:
        description:
        - "Replace DNS Server Response with GSLB Service-IPs"
        required: False
    dns_addition_mx:
        description:
        - "Append MX Records in Addition Section"
        required: False
    backup_alias:
        description:
        - "Return alias name when fail"
        required: False
    server_any:
        description:
        - "Provide All Records"
        required: False
    hint:
        description:
        - "'none'= None; 'answer'= Append Hint Records in DNS Answer Section; 'addition'= Append Hint Records in DNS Addition Section; "
        required: False
    cache:
        description:
        - "Cache DNS Server response"
        required: False
    external_ip:
        description:
        - "Return DNS response with external IP address"
        required: False
    server_txt:
        description:
        - "Provide TXT Records"
        required: False
    server_addition_mx:
        description:
        - "Append MX Records in Addition Section"
        required: False
    aging_time:
        description:
        - "Specify aging-time, default is TTL in DNS record, unit= second (Aging time, default 0 means using TTL in DNS record as aging time)"
        required: False
    block_action:
        description:
        - "Specify Action"
        required: False
    template:
        description:
        - "Logging template (Logging Template Name)"
        required: False
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            dns_ipv6_mapping_type:
                description:
                - "'addition'= Append Mapped Record in DNS Addition Section; 'answer'= Append Mapped Record in DNS Answer Section; 'exclusive'= Only return AAAA Record; 'replace'= Replace Record with Mapped Record; "
            dns_ipv6_option:
                description:
                - "'mix'= Return both AAAA Record and A Record; 'smart'= Return AAAA Record by DNS Query Type; 'mapping'= Map A Record to AAAA Record; "
    selected_only_value:
        description:
        - "Answer Number"
        required: False
    geoloc_action:
        description:
        - "Apply DNS action by geo-location"
        required: False
    server_ns:
        description:
        - "Provide NS Records"
        required: False
    action_type:
        description:
        - "'drop'= Drop query; 'reject'= Send refuse response; 'ignore'= Send empty response; "
        required: False
    server_naptr:
        description:
        - "Provide NAPTR Records"
        required: False
    active_only:
        description:
        - "Only keep active servers"
        required: False
    block_value:
        description:
        - "Field block_value"
        required: False
        suboptions:
            block_value:
                description:
                - "Specify Type Number"
    server_srv:
        description:
        - "Provide SRV Records"
        required: False
    server_auto_ptr:
        description:
        - "Provide PTR Records automatically"
        required: False
    server_cname:
        description:
        - "Provide CNAME Records"
        required: False
    server_authoritative:
        description:
        - "As authoritative server"
        required: False
    server_full_list:
        description:
        - "Append All A Records in Authoritative Section"
        required: False
    server_any_with_metric:
        description:
        - "Provide All Records with GSLB Metrics applied to A/AAAA Records"
        required: False
    dns_auto_map:
        description:
        - "Automatically build DNS Infrastructure"
        required: False
    block_type:
        description:
        - "Field block_type"
        required: False
    sticky_mask:
        description:
        - "Specify IP mask, default is /32"
        required: False
    geoloc_alias:
        description:
        - "Return alias name by geo-location"
        required: False
    logging:
        description:
        - "'none'= None; 'query'= DNS Query; 'response'= DNS Response; 'both'= Both DNS Query and Response; "
        required: False
    backup_server:
        description:
        - "Return fallback server when fail"
        required: False
    sticky_aging_time:
        description:
        - "Specify aging-time, unit= min, default is 5 (Aging time)"
        required: False
    geoloc_policy:
        description:
        - "Apply different policy by geo-location"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    server:
        description:
        - "Run GSLB as DNS server mode"
        required: False
    dynamic_weight:
        description:
        - "dynamically change the weight"
        required: False
    server_ns_list:
        description:
        - "Append All NS Records in Authoritative Section"
        required: False
    server_auto_ns:
        description:
        - "Provide A-Records for NS-Records automatically"
        required: False
    action:
        description:
        - "Apply DNS action for service"
        required: False
    proxy_block_port_range_list:
        description:
        - "Field proxy_block_port_range_list"
        required: False
        suboptions:
            proxy_block_range_from:
                description:
                - "Specify Type Range (From)"
            proxy_block_range_to:
                description:
                - "To"
    server_mx:
        description:
        - "Provide MX Records"
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
AVAILABLE_PROPERTIES = ["action","action_type","active_only","active_only_fail_safe","aging_time","backup_alias","backup_server","block_action","block_type","block_value","cache","cname_detect","delegation","dns_addition_mx","dns_auto_map","dynamic_preference","dynamic_weight","external_ip","external_soa","geoloc_action","geoloc_alias","geoloc_policy","hint","ip_replace","ipv6","logging","proxy_block_port_range_list","selected_only","selected_only_value","server","server_addition_mx","server_any","server_any_with_metric","server_authoritative","server_auto_ns","server_auto_ptr","server_cname","server_full_list","server_mode_only","server_mx","server_naptr","server_ns","server_ns_list","server_ptr","server_sec","server_srv","server_txt","sticky","sticky_aging_time","sticky_ipv6_mask","sticky_mask","template","ttl","use_server_ttl","uuid",]

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
        server_mode_only=dict(type='bool',),
        external_soa=dict(type='bool',),
        server_sec=dict(type='bool',),
        sticky_ipv6_mask=dict(type='int',),
        sticky=dict(type='bool',),
        delegation=dict(type='bool',),
        active_only_fail_safe=dict(type='bool',),
        cname_detect=dict(type='bool',),
        ttl=dict(type='int',),
        dynamic_preference=dict(type='bool',),
        use_server_ttl=dict(type='bool',),
        server_ptr=dict(type='bool',),
        selected_only=dict(type='bool',),
        ip_replace=dict(type='bool',),
        dns_addition_mx=dict(type='bool',),
        backup_alias=dict(type='bool',),
        server_any=dict(type='bool',),
        hint=dict(type='str',choices=['none','answer','addition']),
        cache=dict(type='bool',),
        external_ip=dict(type='bool',),
        server_txt=dict(type='bool',),
        server_addition_mx=dict(type='bool',),
        aging_time=dict(type='int',),
        block_action=dict(type='bool',),
        template=dict(type='str',),
        ipv6=dict(type='list',dns_ipv6_mapping_type=dict(type='str',choices=['addition','answer','exclusive','replace']),dns_ipv6_option=dict(type='str',choices=['mix','smart','mapping'])),
        selected_only_value=dict(type='int',),
        geoloc_action=dict(type='bool',),
        server_ns=dict(type='bool',),
        action_type=dict(type='str',choices=['drop','reject','ignore']),
        server_naptr=dict(type='bool',),
        active_only=dict(type='bool',),
        block_value=dict(type='list',block_value=dict(type='int',)),
        server_srv=dict(type='bool',),
        server_auto_ptr=dict(type='bool',),
        server_cname=dict(type='bool',),
        server_authoritative=dict(type='bool',),
        server_full_list=dict(type='bool',),
        server_any_with_metric=dict(type='bool',),
        dns_auto_map=dict(type='bool',),
        block_type=dict(type='str',choices=['a','aaaa','ns','mx','srv','cname','ptr','soa','txt']),
        sticky_mask=dict(type='str',),
        geoloc_alias=dict(type='bool',),
        logging=dict(type='str',choices=['none','query','response','both']),
        backup_server=dict(type='bool',),
        sticky_aging_time=dict(type='int',),
        geoloc_policy=dict(type='bool',),
        uuid=dict(type='str',),
        server=dict(type='bool',),
        dynamic_weight=dict(type='bool',),
        server_ns_list=dict(type='bool',),
        server_auto_ns=dict(type='bool',),
        action=dict(type='bool',),
        proxy_block_port_range_list=dict(type='list',proxy_block_range_from=dict(type='int',),proxy_block_range_to=dict(type='int',)),
        server_mx=dict(type='bool',)
    ))
   
    # Parent keys
    rv.update(dict(
        policy_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy/{policy_name}/dns"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{policy_name}/dns"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

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
        for k, v in payload["dns"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["dns"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["dns"][k] = v
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
    payload = build_json("dns", module)
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

def replace(module, result, existing_config):
    payload = build_json("dns", module)
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