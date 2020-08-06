#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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
        - "Specify duration in seconds cached content valid, default is 3600 seconds
          (seconds that the cached content is valid (default 3600 seconds))"
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
                - "Specify Local URI for caching (Specify URI pattern that the policy should be
          applied to, maximum 63 charaters)"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Cache hits; 'miss'= Cache misses; 'bytes_served'= Bytes
          served from cache; 'total_req'= Total requests received; 'caching_req'= Total
          requests to cache; 'nc_req_header'= nc_req_header; 'nc_res_header'=
          nc_res_header; 'rv_success'= rv_success; 'rv_failure'= rv_failure;
          'ims_request'= ims_request; 'nm_response'= nm_response; 'rsp_type_CL'=
          rsp_type_CL; 'rsp_type_CE'= rsp_type_CE; 'rsp_type_304'= rsp_type_304;
          'rsp_type_other'= rsp_type_other; 'rsp_no_compress'= rsp_no_compress;
          'rsp_gzip'= rsp_gzip; 'rsp_deflate'= rsp_deflate; 'rsp_other'= rsp_other;
          'nocache_match'= nocache_match; 'match'= match; 'invalidate_match'=
          invalidate_match; 'content_toobig'= content_toobig; 'content_toosmall'=
          content_toosmall; 'entry_create_failures'= entry_create_failures; 'mem_size'=
          mem_size; 'entry_num'= entry_num; 'replaced_entry'= replaced_entry;
          'aging_entry'= aging_entry; 'cleaned_entry'= cleaned_entry;"
    replacement_policy:
        description:
        - "'LFU'= LFU;"
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
        - "Specify maximum cache size in megabytes, default is 80MB (RAM cache size in
          megabytes (default 80MB))"
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
                - "'cache'= Specify if certain URIs should be cached; 'nocache'= Specify if
          certain URIs should not be cached;"
            cache_value:
                description:
                - "Specify seconds that content should be cached, default is age specified in
          cache template"
            uri:
                description:
                - "Specify URI for cache policy (Specify URI pattern that the policy should be
          applied to, maximum 63 charaters)"
            invalidate:
                description:
                - "Specify if URI should invalidate cache entries matching pattern (pattern that
          would match entries to be invalidated (64 chars max))"
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
AVAILABLE_PROPERTIES = [
    "accept_reload_req",
    "age",
    "default_policy_nocache",
    "disable_insert_age",
    "disable_insert_via",
    "local_uri_policy",
    "logging",
    "max_cache_size",
    "max_content_size",
    "min_content_size",
    "name",
    "remove_cookies",
    "replacement_policy",
    "sampling_enable",
    "stats",
    "uri_policy",
    "user_tag",
    "uuid",
    "verify_host",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'stats': {
            'type': 'dict',
            'nm_response': {
                'type': 'str',
            },
            'rsp_type_304': {
                'type': 'str',
            },
            'rsp_other': {
                'type': 'str',
            },
            'content_toosmall': {
                'type': 'str',
            },
            'entry_create_failures': {
                'type': 'str',
            },
            'nocache_match': {
                'type': 'str',
            },
            'content_toobig': {
                'type': 'str',
            },
            'replaced_entry': {
                'type': 'str',
            },
            'miss': {
                'type': 'str',
            },
            'nc_req_header': {
                'type': 'str',
            },
            'aging_entry': {
                'type': 'str',
            },
            'mem_size': {
                'type': 'str',
            },
            'rsp_deflate': {
                'type': 'str',
            },
            'invalidate_match': {
                'type': 'str',
            },
            'match': {
                'type': 'str',
            },
            'cleaned_entry': {
                'type': 'str',
            },
            'entry_num': {
                'type': 'str',
            },
            'total_req': {
                'type': 'str',
            },
            'bytes_served': {
                'type': 'str',
            },
            'rv_success': {
                'type': 'str',
            },
            'rv_failure': {
                'type': 'str',
            },
            'rsp_gzip': {
                'type': 'str',
            },
            'hits': {
                'type': 'str',
            },
            'rsp_type_other': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'rsp_type_CE': {
                'type': 'str',
            },
            'rsp_type_CL': {
                'type': 'str',
            },
            'rsp_no_compress': {
                'type': 'str',
            },
            'nc_res_header': {
                'type': 'str',
            },
            'caching_req': {
                'type': 'str',
            },
            'ims_request': {
                'type': 'str',
            }
        },
        'accept_reload_req': {
            'type': 'bool',
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'default_policy_nocache': {
            'type': 'bool',
        },
        'age': {
            'type': 'int',
        },
        'disable_insert_via': {
            'type': 'bool',
        },
        'user_tag': {
            'type': 'str',
        },
        'local_uri_policy': {
            'type': 'list',
            'local_uri': {
                'type': 'str',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'hits', 'miss', 'bytes_served', 'total_req',
                    'caching_req', 'nc_req_header', 'nc_res_header',
                    'rv_success', 'rv_failure', 'ims_request', 'nm_response',
                    'rsp_type_CL', 'rsp_type_CE', 'rsp_type_304',
                    'rsp_type_other', 'rsp_no_compress', 'rsp_gzip',
                    'rsp_deflate', 'rsp_other', 'nocache_match', 'match',
                    'invalidate_match', 'content_toobig', 'content_toosmall',
                    'entry_create_failures', 'mem_size', 'entry_num',
                    'replaced_entry', 'aging_entry', 'cleaned_entry'
                ]
            }
        },
        'replacement_policy': {
            'type': 'str',
            'choices': ['LFU']
        },
        'disable_insert_age': {
            'type': 'bool',
        },
        'max_content_size': {
            'type': 'int',
        },
        'max_cache_size': {
            'type': 'int',
        },
        'logging': {
            'type': 'str',
        },
        'uri_policy': {
            'type': 'list',
            'cache_action': {
                'type': 'str',
                'choices': ['cache', 'nocache']
            },
            'cache_value': {
                'type': 'int',
            },
            'uri': {
                'type': 'str',
            },
            'invalidate': {
                'type': 'str',
            }
        },
        'remove_cookies': {
            'type': 'bool',
        },
        'verify_host': {
            'type': 'bool',
        },
        'min_content_size': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        }
    })
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
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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

    for k, v in param.items():
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
    return {title: data}


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
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
                    if result["changed"] is not True:
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

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
