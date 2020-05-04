#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_rc_cache_global
description:
    - global ram cache stats
short_description: Configures A10 slb.rc-cache-global
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Cache Hits; 'miss'= Cache Misses; 'bytes_served'= Bytes Served; 'total_req'= Total Requests; 'caching_req'= Cacheable Requests; 'nc_req_header'= No-cache Request; 'nc_res_header'= Not cacheable; 'rv_success'= Revalidation Successes; 'rv_failure'= Revalidation Failures; 'ims_request'= IMS Requests; 'nm_response'= Responses from cache 304 Not Modified; 'rsp_type_CL'= Responses from server 200 OK - Cont Len; 'rsp_type_CE'= Responses from server 200 OK - Chnk Enc; 'rsp_type_304'= Responses from server 304 Not Modified; 'rsp_type_other'= Responses from server 200 OK - Other; 'rsp_no_compress'= Responses from cache 200 OK - No Comp; 'rsp_gzip'= Responses from cache 200 OK - Gzip; 'rsp_deflate'= Responses from cache 200 OK - Deflate; 'rsp_other'= Responses from cache Other; 'nocache_match'= Policy URI nocache; 'match'= Policy URI cache; 'invalidate_match'= Policy URI invalidate; 'content_toobig'= Policy Content Too Big; 'content_toosmall'= Policy Content Too Small; 'entry_create_failures'= Entry Create failures; 'mem_size'= Memory Used; 'entry_num'= Entry Cached; 'replaced_entry'= Entry Replaced; 'aging_entry'= Entry Aged Out; 'cleaned_entry'= Entry Cleaned; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            nm_response:
                description:
                - "Responses from cache 304 Not Modified"
            rsp_type_304:
                description:
                - "Responses from server 304 Not Modified"
            rsp_other:
                description:
                - "Responses from cache Other"
            content_toosmall:
                description:
                - "Policy Content Too Small"
            entry_create_failures:
                description:
                - "Entry Create failures"
            nocache_match:
                description:
                - "Policy URI nocache"
            content_toobig:
                description:
                - "Policy Content Too Big"
            replaced_entry:
                description:
                - "Entry Replaced"
            miss:
                description:
                - "Cache Misses"
            nc_req_header:
                description:
                - "No-cache Request"
            aging_entry:
                description:
                - "Entry Aged Out"
            mem_size:
                description:
                - "Memory Used"
            rsp_deflate:
                description:
                - "Responses from cache 200 OK - Deflate"
            invalidate_match:
                description:
                - "Policy URI invalidate"
            match:
                description:
                - "Policy URI cache"
            cleaned_entry:
                description:
                - "Entry Cleaned"
            entry_num:
                description:
                - "Entry Cached"
            total_req:
                description:
                - "Total Requests"
            bytes_served:
                description:
                - "Bytes Served"
            rv_success:
                description:
                - "Revalidation Successes"
            rv_failure:
                description:
                - "Revalidation Failures"
            rsp_gzip:
                description:
                - "Responses from cache 200 OK - Gzip"
            hits:
                description:
                - "Cache Hits"
            rsp_type_other:
                description:
                - "Responses from server 200 OK - Other"
            rsp_type_CE:
                description:
                - "Responses from server 200 OK - Chnk Enc"
            rsp_type_CL:
                description:
                - "Responses from server 200 OK - Cont Len"
            rsp_no_compress:
                description:
                - "Responses from cache 200 OK - No Comp"
            nc_res_header:
                description:
                - "Not cacheable"
            caching_req:
                description:
                - "Cacheable Requests"
            ims_request:
                description:
                - "IMS Requests"
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
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','hits','miss','bytes_served','total_req','caching_req','nc_req_header','nc_res_header','rv_success','rv_failure','ims_request','nm_response','rsp_type_CL','rsp_type_CE','rsp_type_304','rsp_type_other','rsp_no_compress','rsp_gzip','rsp_deflate','rsp_other','nocache_match','match','invalidate_match','content_toobig','content_toosmall','entry_create_failures','mem_size','entry_num','replaced_entry','aging_entry','cleaned_entry'])),
        stats=dict(type='dict', nm_response=dict(type='str', ),rsp_type_304=dict(type='str', ),rsp_other=dict(type='str', ),content_toosmall=dict(type='str', ),entry_create_failures=dict(type='str', ),nocache_match=dict(type='str', ),content_toobig=dict(type='str', ),replaced_entry=dict(type='str', ),miss=dict(type='str', ),nc_req_header=dict(type='str', ),aging_entry=dict(type='str', ),mem_size=dict(type='str', ),rsp_deflate=dict(type='str', ),invalidate_match=dict(type='str', ),match=dict(type='str', ),cleaned_entry=dict(type='str', ),entry_num=dict(type='str', ),total_req=dict(type='str', ),bytes_served=dict(type='str', ),rv_success=dict(type='str', ),rv_failure=dict(type='str', ),rsp_gzip=dict(type='str', ),hits=dict(type='str', ),rsp_type_other=dict(type='str', ),rsp_type_CE=dict(type='str', ),rsp_type_CL=dict(type='str', ),rsp_no_compress=dict(type='str', ),nc_res_header=dict(type='str', ),caching_req=dict(type='str', ),ims_request=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/rc-cache-global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/rc-cache-global"

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["rc-cache-global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rc-cache-global"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rc-cache-global"][k] = v
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
    payload = build_json("rc-cache-global", module)
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