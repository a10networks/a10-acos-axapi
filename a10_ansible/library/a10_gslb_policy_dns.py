#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_policy_dns
description:
    - None
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
    server_mode_only:
        description:
        - "None"
        required: False
    external_soa:
        description:
        - "None"
        required: False
    server_sec:
        description:
        - "None"
        required: False
    sticky_ipv6_mask:
        description:
        - "None"
        required: False
    sticky:
        description:
        - "None"
        required: False
    delegation:
        description:
        - "None"
        required: False
    active_only_fail_safe:
        description:
        - "None"
        required: False
    cname_detect:
        description:
        - "None"
        required: False
    ttl:
        description:
        - "None"
        required: False
    dynamic_preference:
        description:
        - "None"
        required: False
    use_server_ttl:
        description:
        - "None"
        required: False
    server_ptr:
        description:
        - "None"
        required: False
    selected_only:
        description:
        - "None"
        required: False
    ip_replace:
        description:
        - "None"
        required: False
    dns_addition_mx:
        description:
        - "None"
        required: False
    backup_alias:
        description:
        - "None"
        required: False
    server_any:
        description:
        - "None"
        required: False
    hint:
        description:
        - "None"
        required: False
    cache:
        description:
        - "None"
        required: False
    external_ip:
        description:
        - "None"
        required: False
    server_txt:
        description:
        - "None"
        required: False
    server_addition_mx:
        description:
        - "None"
        required: False
    aging_time:
        description:
        - "None"
        required: False
    block_action:
        description:
        - "None"
        required: False
    template:
        description:
        - "None"
        required: False
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            dns_ipv6_mapping_type:
                description:
                - "None"
            dns_ipv6_option:
                description:
                - "None"
    selected_only_value:
        description:
        - "None"
        required: False
    geoloc_action:
        description:
        - "None"
        required: False
    server_ns:
        description:
        - "None"
        required: False
    action_type:
        description:
        - "None"
        required: False
    server_naptr:
        description:
        - "None"
        required: False
    active_only:
        description:
        - "None"
        required: False
    block_value:
        description:
        - "Field block_value"
        required: False
        suboptions:
            block_value:
                description:
                - "None"
    server_srv:
        description:
        - "None"
        required: False
    server_auto_ptr:
        description:
        - "None"
        required: False
    server_cname:
        description:
        - "None"
        required: False
    server_authoritative:
        description:
        - "None"
        required: False
    server_full_list:
        description:
        - "None"
        required: False
    dns_auto_map:
        description:
        - "None"
        required: False
    block_type:
        description:
        - "Field block_type"
        required: False
    sticky_mask:
        description:
        - "None"
        required: False
    geoloc_alias:
        description:
        - "None"
        required: False
    logging:
        description:
        - "None"
        required: False
    backup_server:
        description:
        - "None"
        required: False
    sticky_aging_time:
        description:
        - "None"
        required: False
    geoloc_policy:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    server:
        description:
        - "None"
        required: False
    dynamic_weight:
        description:
        - "None"
        required: False
    server_ns_list:
        description:
        - "None"
        required: False
    server_auto_ns:
        description:
        - "None"
        required: False
    action:
        description:
        - "None"
        required: False
    proxy_block_port_range_list:
        description:
        - "Field proxy_block_port_range_list"
        required: False
        suboptions:
            proxy_block_range_from:
                description:
                - "None"
            proxy_block_range_to:
                description:
                - "None"
    server_mx:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["action","action_type","active_only","active_only_fail_safe","aging_time","backup_alias","backup_server","block_action","block_type","block_value","cache","cname_detect","delegation","dns_addition_mx","dns_auto_map","dynamic_preference","dynamic_weight","external_ip","external_soa","geoloc_action","geoloc_alias","geoloc_policy","hint","ip_replace","ipv6","logging","proxy_block_port_range_list","selected_only","selected_only_value","server","server_addition_mx","server_any","server_authoritative","server_auto_ns","server_auto_ptr","server_cname","server_full_list","server_mode_only","server_mx","server_naptr","server_ns","server_ns_list","server_ptr","server_sec","server_srv","server_txt","sticky","sticky_aging_time","sticky_ipv6_mask","sticky_mask","template","ttl","use_server_ttl","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
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

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy/{name}/dns"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{name}/dns"
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("dns", module)
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
    payload = build_json("dns", module)
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