#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_template_cache
description:
    - RAM caching template
short_description: Configures A10 slb.template.cache
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            nm_response:
                description:
                - "Field nm_response"
            rsp_type_304:
                description:
                - "Field rsp_type_304"
            rsp_other:
                description:
                - "Field rsp_other"
            content_toosmall:
                description:
                - "Field content_toosmall"
            entry_create_failures:
                description:
                - "Field entry_create_failures"
            nocache_match:
                description:
                - "Field nocache_match"
            content_toobig:
                description:
                - "Field content_toobig"
            replaced_entry:
                description:
                - "Field replaced_entry"
            miss:
                description:
                - "Cache misses"
            nc_req_header:
                description:
                - "Field nc_req_header"
            aging_entry:
                description:
                - "Field aging_entry"
            mem_size:
                description:
                - "Field mem_size"
            rsp_deflate:
                description:
                - "Field rsp_deflate"
            invalidate_match:
                description:
                - "Field invalidate_match"
            match:
                description:
                - "Field match"
            cleaned_entry:
                description:
                - "Field cleaned_entry"
            entry_num:
                description:
                - "Field entry_num"
            total_req:
                description:
                - "Total requests received"
            bytes_served:
                description:
                - "Bytes served from cache"
            rv_success:
                description:
                - "Field rv_success"
            rv_failure:
                description:
                - "Field rv_failure"
            rsp_gzip:
                description:
                - "Field rsp_gzip"
            hits:
                description:
                - "Cache hits"
            rsp_type_other:
                description:
                - "Field rsp_type_other"
            name:
                description:
                - "Specify cache template name"
            rsp_type_CE:
                description:
                - "Field rsp_type_CE"
            rsp_type_CL:
                description:
                - "Field rsp_type_CL"
            rsp_no_compress:
                description:
                - "Field rsp_no_compress"
            nc_res_header:
                description:
                - "Field nc_res_header"
            caching_req:
                description:
                - "Total requests to cache"
            ims_request:
                description:
                - "Field ims_request"
    accept_reload_req:
        description:
        - "Accept reload requests via cache-control directives in HTTP headers"
        required: False
    name:
        description:
        - "Specify cache template name"
        required: True
    default_policy_nocache:
        description:
        - "Specify default policy to be to not cache"
        required: False
    age:
        description:
        - "Specify duration in seconds cached content valid, default is 3600 seconds (seconds that the cached content is valid (default 3600 seconds))"
        required: False
    disable_insert_via:
        description:
        - "Disable insertion of via header in response served from RAM cache"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    local_uri_policy:
        description:
        - "Field local_uri_policy"
        required: False
        suboptions:
            local_uri:
                description:
                - "Specify Local URI for caching (Specify URI pattern that the policy should be applied to, maximum 63 charaters)"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Cache hits; 'miss'= Cache misses; 'bytes_served'= Bytes served from cache; 'total_req'= Total requests received; 'caching_req'= Total requests to cache; 'nc_req_header'= nc_req_header; 'nc_res_header'= nc_res_header; 'rv_success'= rv_success; 'rv_failure'= rv_failure; 'ims_request'= ims_request; 'nm_response'= nm_response; 'rsp_type_CL'= rsp_type_CL; 'rsp_type_CE'= rsp_type_CE; 'rsp_type_304'= rsp_type_304; 'rsp_type_other'= rsp_type_other; 'rsp_no_compress'= rsp_no_compress; 'rsp_gzip'= rsp_gzip; 'rsp_deflate'= rsp_deflate; 'rsp_other'= rsp_other; 'nocache_match'= nocache_match; 'match'= match; 'invalidate_match'= invalidate_match; 'content_toobig'= content_toobig; 'content_toosmall'= content_toosmall; 'entry_create_failures'= entry_create_failures; 'mem_size'= mem_size; 'entry_num'= entry_num; 'replaced_entry'= replaced_entry; 'aging_entry'= aging_entry; 'cleaned_entry'= cleaned_entry; "
    replacement_policy:
        description:
        - "'LFU'= LFU; "
        required: False
    disable_insert_age:
        description:
        - "Disable insertion of age header in response served from RAM cache"
        required: False
    max_content_size:
        description:
        - "Maximum size (bytes) of response that can be cached - default 81920 (80KB)"
        required: False
    max_cache_size:
        description:
        - "Specify maximum cache size in megabytes, default is 80MB (RAM cache size in megabytes (default 80MB))"
        required: False
    logging:
        description:
        - "Specify logging template (Logging Config name)"
        required: False
    uri_policy:
        description:
        - "Field uri_policy"
        required: False
        suboptions:
            cache_action:
                description:
                - "'cache'= Specify if certain URIs should be cached; 'nocache'= Specify if certain URIs should not be cached; "
            cache_value:
                description:
                - "Specify seconds that content should be cached, default is age specified in cache template"
            uri:
                description:
                - "Specify URI for cache policy (Specify URI pattern that the policy should be applied to, maximum 63 charaters)"
            invalidate:
                description:
                - "Specify if URI should invalidate cache entries matching pattern (pattern that would match entries to be invalidated (64 chars max))"
    remove_cookies:
        description:
        - "Remove cookies in response and cache"
        required: False
    verify_host:
        description:
        - "Verify request using host before sending response from RAM cache"
        required: False
    min_content_size:
        description:
        - "Minimum size (bytes) of response that can be cached - default 512"
        required: False
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["accept_reload_req","age","default_policy_nocache","disable_insert_age","disable_insert_via","local_uri_policy","logging","max_cache_size","max_content_size","min_content_size","name","remove_cookies","replacement_policy","sampling_enable","stats","uri_policy","user_tag","uuid","verify_host",]

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
        stats=dict(type='dict', nm_response=dict(type='str', ), rsp_type_304=dict(type='str', ), rsp_other=dict(type='str', ), content_toosmall=dict(type='str', ), entry_create_failures=dict(type='str', ), nocache_match=dict(type='str', ), content_toobig=dict(type='str', ), replaced_entry=dict(type='str', ), miss=dict(type='str', ), nc_req_header=dict(type='str', ), aging_entry=dict(type='str', ), mem_size=dict(type='str', ), rsp_deflate=dict(type='str', ), invalidate_match=dict(type='str', ), match=dict(type='str', ), cleaned_entry=dict(type='str', ), entry_num=dict(type='str', ), total_req=dict(type='str', ), bytes_served=dict(type='str', ), rv_success=dict(type='str', ), rv_failure=dict(type='str', ), rsp_gzip=dict(type='str', ), hits=dict(type='str', ), rsp_type_other=dict(type='str', ), name=dict(type='str', required=True, ), rsp_type_CE=dict(type='str', ), rsp_type_CL=dict(type='str', ), rsp_no_compress=dict(type='str', ), nc_res_header=dict(type='str', ), caching_req=dict(type='str', ), ims_request=dict(type='str', )),
        accept_reload_req=dict(type='bool', ),
        name=dict(type='str', required=True, ),
        default_policy_nocache=dict(type='bool', ),
        age=dict(type='int', ),
        disable_insert_via=dict(type='bool', ),
        user_tag=dict(type='str', ),
        local_uri_policy=dict(type='list', local_uri=dict(type='str', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits', 'miss', 'bytes_served', 'total_req', 'caching_req', 'nc_req_header', 'nc_res_header', 'rv_success', 'rv_failure', 'ims_request', 'nm_response', 'rsp_type_CL', 'rsp_type_CE', 'rsp_type_304', 'rsp_type_other', 'rsp_no_compress', 'rsp_gzip', 'rsp_deflate', 'rsp_other', 'nocache_match', 'match', 'invalidate_match', 'content_toobig', 'content_toosmall', 'entry_create_failures', 'mem_size', 'entry_num', 'replaced_entry', 'aging_entry', 'cleaned_entry'])),
        replacement_policy=dict(type='str', choices=['LFU']),
        disable_insert_age=dict(type='bool', ),
        max_content_size=dict(type='int', ),
        max_cache_size=dict(type='int', ),
        logging=dict(type='str', ),
        uri_policy=dict(type='list', cache_action=dict(type='str', choices=['cache', 'nocache']), cache_value=dict(type='int', ), uri=dict(type='str', ), invalidate=dict(type='str', )),
        remove_cookies=dict(type='bool', ),
        verify_host=dict(type='bool', ),
        min_content_size=dict(type='int', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["cache"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["cache"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["cache"][k] = v
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
    payload = build_json("cache", module)
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