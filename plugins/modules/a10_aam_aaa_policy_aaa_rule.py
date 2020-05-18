#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_aaa_policy_aaa_rule
description:
    - Rules of AAA policy
short_description: Configures A10 aam.aaa.policy.aaa-rule
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    ansible_protocol:
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
    aaa_policy_name:
        description:
        - Key to identify parent object
    index:
        description:
        - "Specify AAA rule index"
        required: True
    match_encoded_uri:
        description:
        - "Enable URL decoding for URI matching"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            index:
                description:
                - "Specify AAA rule index"
            hit_auth:
                description:
                - "Field hit_auth"
            hit_bypass:
                description:
                - "Field hit_bypass"
            total_count:
                description:
                - "Field total_count"
            hit_deny:
                description:
                - "Field hit_deny"
            failure_bypass:
                description:
                - "Field failure_bypass"
    uuid:
        description:
        - "uuid of the object"
        required: False
    authorize_policy:
        description:
        - "Specify authorization policy to bind to the AAA rule"
        required: False
    uri:
        description:
        - "Field uri"
        required: False
        suboptions:
            match_type:
                description:
                - "'contains'= Match URI if request URI contains specified URI; 'ends-with'= Match URI if request URI ends with specified URI; 'equals'= Match URI if request URI equals specified URI; 'starts-with'= Match URI if request URI starts with specified URI; "
            uri_str:
                description:
                - "Specify URI string"
    user_tag:
        description:
        - "Customized tag"
        required: False
    user_agent:
        description:
        - "Field user_agent"
        required: False
        suboptions:
            user_agent_str:
                description:
                - "Specify request User-Agent string"
            user_agent_match_type:
                description:
                - "'contains'= Match request User-Agent header if it contains specified string; 'ends-with'= Match request User-Agent header if it ends with specified string; 'equals'= Match request User-Agent header if it equals specified string; 'starts-with'= Match request User-Agent header if it starts with specified string; "
    host:
        description:
        - "Field host"
        required: False
        suboptions:
            host_str:
                description:
                - "Specify URI string"
            host_match_type:
                description:
                - "'contains'= Match HOST if request HTTP HOST header contains specified hostname; 'ends-with'= Match HOST if request HTTP HOST header ends with specified hostname; 'equals'= Match HOST if request HTTP HOST header equals specified hostname; 'starts-with'= Match HOST if request HTTP HOST header starts with specified hostname; "
    access_list:
        description:
        - "Field access_list"
        required: False
        suboptions:
            acl_name:
                description:
                - "'ip-name'= Apply an IP named access list; 'ipv6-name'= Apply an IPv6 named access list; "
            acl_id:
                description:
                - "ACL id"
            name:
                description:
                - "Specify Named Access List"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total_count'= total_count; 'hit_deny'= hit_deny; 'hit_auth'= hit_auth; 'hit_bypass'= hit_bypass; 'failure_bypass'= failure_bypass; "
    auth_failure_bypass:
        description:
        - "Forward client’s request even though authentication has failed"
        required: False
    authentication_template:
        description:
        - "Specify authentication template name to bind to the AAA rule"
        required: False
    action:
        description:
        - "'allow'= Allow traffic that matches this rule; 'deny'= Deny traffic that matches this rule; "
        required: False
    port:
        description:
        - "Specify port number for aaa-rule, default is 0 for all port numbers"
        required: False
    domain_name:
        description:
        - "Specify domain name to bind to the AAA rule (ex= a10networks.com, www.a10networks.com)"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["access_list","action","auth_failure_bypass","authentication_template","authorize_policy","domain_name","host","index","match_encoded_uri","port","sampling_enable","stats","uri","user_agent","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        index=dict(type='int', required=True, ),
        match_encoded_uri=dict(type='bool', ),
        stats=dict(type='dict', index=dict(type='int', required=True, ), hit_auth=dict(type='str', ), hit_bypass=dict(type='str', ), total_count=dict(type='str', ), hit_deny=dict(type='str', ), failure_bypass=dict(type='str', )),
        uuid=dict(type='str', ),
        authorize_policy=dict(type='str', ),
        uri=dict(type='list', match_type=dict(type='str', choices=['contains', 'ends-with', 'equals', 'starts-with']), uri_str=dict(type='str', )),
        user_tag=dict(type='str', ),
        user_agent=dict(type='list', user_agent_str=dict(type='str', ), user_agent_match_type=dict(type='str', choices=['contains', 'ends-with', 'equals', 'starts-with'])),
        host=dict(type='list', host_str=dict(type='str', ), host_match_type=dict(type='str', choices=['contains', 'ends-with', 'equals', 'starts-with'])),
        access_list=dict(type='dict', acl_name=dict(type='str', choices=['ip-name', 'ipv6-name']), acl_id=dict(type='int', ), name=dict(type='str', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'total_count', 'hit_deny', 'hit_auth', 'hit_bypass', 'failure_bypass'])),
        auth_failure_bypass=dict(type='bool', ),
        authentication_template=dict(type='str', ),
        action=dict(type='str', choices=['allow', 'deny']),
        port=dict(type='int', ),
        domain_name=dict(type='str', )
    ))
   
    # Parent keys
    rv.update(dict(
        aaa_policy_name=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/aaa-policy/{aaa_policy_name}/aaa-rule/{index}"

    f_dict = {}
    f_dict["index"] = module.params["index"]
    f_dict["aaa_policy_name"] = module.params["aaa_policy_name"]

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
    url_base = "/axapi/v3/aam/aaa-policy/{aaa_policy_name}/aaa-rule/{index}"

    f_dict = {}
    f_dict["index"] = ""
    f_dict["aaa_policy_name"] = module.params["aaa_policy_name"]

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
        for k, v in payload["aaa-rule"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["aaa-rule"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["aaa-rule"][k] = v
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
    payload = build_json("aaa-rule", module)
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
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

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
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