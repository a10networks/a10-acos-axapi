#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_dns
description:
    - DNS template
short_description: Configures A10 slb.template.dns
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
    dnssec_service_group:
        description:
        - "Use different service group if DNSSEC DO bit set (Service Group Name)"
        required: False
    name:
        description:
        - "DNS Template Name"
        required: True
    class_list:
        description:
        - "Field class_list"
        required: False
        suboptions:
            lid_list:
                description:
                - "Field lid_list"
            name:
                description:
                - "Specify a class list name"
            uuid:
                description:
                - "uuid of the object"
    response_rate_limiting:
        description:
        - "Field response_rate_limiting"
        required: False
        suboptions:
            filter_response_rate:
                description:
                - "Maximum allowed request rate for the filter. This should match average traffic. (default 20 per two seconds)"
            slip_rate:
                description:
                - "Every n'th response that would be rate-limited will be let through instead"
            response_rate:
                description:
                - "Responses exceeding this rate within the window will be dropped (default 5 per second)"
            window:
                description:
                - "Rate-Limiting Interval in Seconds (default is one)"
            action:
                description:
                - "'log-only'= Only log rate-limiting, do not actually rate limit. Requires enable-log configuration; 'rate-limit'= Rate-Limit based on configuration (Default); 'whitelist'= Whitelist, disable rate-limiting; "
            enable_log:
                description:
                - "Enable logging"
            uuid:
                description:
                - "uuid of the object"
    drop:
        description:
        - "Drop the malformed query"
        required: False
    period:
        description:
        - "Period in minutes"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    query_id_switch:
        description:
        - "Use DNS query ID to create sesion"
        required: False
    enable_cache_sharing:
        description:
        - "Enable DNS cache sharing"
        required: False
    redirect_to_tcp_port:
        description:
        - "Direct the client to retry with TCP for DNS UDP request"
        required: False
    max_query_length:
        description:
        - "Define Maximum DNS Query Length, default is unlimited (Specify Maximum Length)"
        required: False
    disable_dns_template:
        description:
        - "Disable DNS template"
        required: False
    forward:
        description:
        - "Forward to service group (Service group name)"
        required: False
    max_cache_size:
        description:
        - "Define maximum cache size (Maximum cache entry per VIP)"
        required: False
    default_policy:
        description:
        - "'nocache'= Cache disable; 'cache'= Cache enable; "
        required: False
    max_cache_entry_size:
        description:
        - "Define maximum cache entry size (Maximum cache entry size per VIP)"
        required: False
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["class_list","default_policy","disable_dns_template","dnssec_service_group","drop","enable_cache_sharing","forward","max_cache_entry_size","max_cache_size","max_query_length","name","period","query_id_switch","redirect_to_tcp_port","response_rate_limiting","user_tag","uuid",]

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
        dnssec_service_group=dict(type='str',),
        name=dict(type='str',required=True,),
        class_list=dict(type='dict',lid_list=dict(type='list',action_value=dict(type='str',choices=['dns-cache-disable','dns-cache-enable','forward']),log=dict(type='bool',),lidnum=dict(type='int',required=True,),over_limit_action=dict(type='bool',),per=dict(type='int',),lockout=dict(type='int',),user_tag=dict(type='str',),dns=dict(type='dict',cache_action=dict(type='str',choices=['cache-disable','cache-enable']),honor_server_response_ttl=dict(type='bool',),weight=dict(type='int',),ttl=dict(type='int',)),conn_rate_limit=dict(type='int',),log_interval=dict(type='int',),uuid=dict(type='str',)),name=dict(type='str',),uuid=dict(type='str',)),
        response_rate_limiting=dict(type='dict',filter_response_rate=dict(type='int',),slip_rate=dict(type='int',),response_rate=dict(type='int',),window=dict(type='int',),action=dict(type='str',choices=['log-only','rate-limit','whitelist']),enable_log=dict(type='bool',),uuid=dict(type='str',)),
        drop=dict(type='bool',),
        period=dict(type='int',),
        user_tag=dict(type='str',),
        query_id_switch=dict(type='bool',),
        enable_cache_sharing=dict(type='bool',),
        redirect_to_tcp_port=dict(type='bool',),
        max_query_length=dict(type='int',),
        disable_dns_template=dict(type='bool',),
        forward=dict(type='str',),
        max_cache_size=dict(type='int',),
        default_policy=dict(type='str',choices=['nocache','cache']),
        max_cache_entry_size=dict(type='int',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/dns/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/dns/{name}"

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

def replace(module, result, existing_config, payload):
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