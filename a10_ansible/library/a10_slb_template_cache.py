#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["accept_reload_req","age","default_policy_nocache","disable_insert_age","disable_insert_via","local_uri_policy","logging","max_cache_size","max_content_size","min_content_size","name","remove_cookies","replacement_policy","sampling_enable","uri_policy","user_tag","uuid","verify_host",]

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
        accept_reload_req=dict(type='bool',),
        name=dict(type='str',required=True,),
        default_policy_nocache=dict(type='bool',),
        age=dict(type='int',),
        disable_insert_via=dict(type='bool',),
        user_tag=dict(type='str',),
        local_uri_policy=dict(type='list',local_uri=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits','miss','bytes_served','total_req','caching_req','nc_req_header','nc_res_header','rv_success','rv_failure','ims_request','nm_response','rsp_type_CL','rsp_type_CE','rsp_type_304','rsp_type_other','rsp_no_compress','rsp_gzip','rsp_deflate','rsp_other','nocache_match','match','invalidate_match','content_toobig','content_toosmall','entry_create_failures','mem_size','entry_num','replaced_entry','aging_entry','cleaned_entry'])),
        replacement_policy=dict(type='str',choices=['LFU']),
        disable_insert_age=dict(type='bool',),
        max_content_size=dict(type='int',),
        max_cache_size=dict(type='int',),
        logging=dict(type='str',),
        uri_policy=dict(type='list',cache_action=dict(type='str',choices=['cache','nocache']),cache_value=dict(type='int',),uri=dict(type='str',),invalidate=dict(type='str',)),
        remove_cookies=dict(type='bool',),
        verify_host=dict(type='bool',),
        min_content_size=dict(type='int',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    payload = build_json("cache", module)
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
    payload = build_json("cache", module)
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
    payload = build_json("cache", module)
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