#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_cache
description:
    - RAM caching template
author: A10 Networks
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "Specify cache template name"
        type: str
        required: True
    accept_reload_req:
        description:
        - "Accept reload requests via cache-control directives in HTTP headers"
        type: bool
        required: False
    age:
        description:
        - "Specify duration in seconds cached content valid, default is 3600 seconds
          (seconds that the cached content is valid (default 3600 seconds))"
        type: int
        required: False
    default_policy_nocache:
        description:
        - "Specify default policy to be to not cache"
        type: bool
        required: False
    disable_insert_age:
        description:
        - "Disable insertion of age header in response served from RAM cache"
        type: bool
        required: False
    disable_insert_via:
        description:
        - "Disable insertion of via header in response served from RAM cache"
        type: bool
        required: False
    max_cache_size:
        description:
        - "Specify maximum cache size in megabytes, default is 80MB (RAM cache size in
          megabytes (default 80MB))"
        type: int
        required: False
    min_content_size:
        description:
        - "Minimum size (bytes) of response that can be cached - default 512"
        type: int
        required: False
    max_content_size:
        description:
        - "Maximum size (bytes) of response that can be cached - default 81920 (80KB)"
        type: int
        required: False
    local_uri_policy:
        description:
        - "Field local_uri_policy"
        type: list
        required: False
        suboptions:
            local_uri:
                description:
                - "Specify Local URI for caching (Specify URI pattern that the policy should be
          applied to, maximum 63 charaters)"
                type: str
    uri_policy:
        description:
        - "Field uri_policy"
        type: list
        required: False
        suboptions:
            uri:
                description:
                - "Specify URI for cache policy (Specify URI pattern that the policy should be
          applied to, maximum 63 charaters)"
                type: str
            cache_action:
                description:
                - "'cache'= Specify if certain URIs should be cached; 'nocache'= Specify if
          certain URIs should not be cached;"
                type: str
            cache_value:
                description:
                - "Specify seconds that content should be cached, default is age specified in
          cache template"
                type: int
            invalidate:
                description:
                - "Specify if URI should invalidate cache entries matching pattern (pattern that
          would match entries to be invalidated (64 chars max))"
                type: str
    remove_cookies:
        description:
        - "Remove cookies in response and cache"
        type: bool
        required: False
    replacement_policy:
        description:
        - "'LFU'= LFU;"
        type: str
        required: False
    logging:
        description:
        - "Specify logging template (Logging Config name)"
        type: str
        required: False
    verify_host:
        description:
        - "Verify request using host before sending response from RAM cache"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Cache hits; 'miss'= Cache misses; 'bytes_served'= Bytes
          served from cache; 'total_req'= Total requests received; 'caching_req'= Total
          requests to cache; 'nc_req_header'= slbTemplateCacheNcReqHeader, help
          nc_req_header; 'nc_res_header'= slbTemplateCacheNcResHeader, help
          nc_res_header; 'rv_success'= some help string; 'rv_failure'=
          slbTemplateCacheRvFailure, help rv_failure; 'ims_request'= some help string;
          'nm_response'= some help string; 'rsp_type_CL'= some help string;
          'rsp_type_CE'= some help string; 'rsp_type_304'= some help string;
          'rsp_type_other'= some help string; 'rsp_no_compress'= some help string;
          'rsp_gzip'= some help string; 'rsp_deflate'= some help string; 'rsp_other'=
          some help string; 'nocache_match'= some help string; 'match'= some help string;
          'invalidate_match'= some help string; 'content_toobig'=
          slbTemplateCacheContentToobig, help content_toobig; 'content_toosmall'=
          slbTemplateCacheContentToosmall, help content_toosmall;
          'entry_create_failures'= slbTemplateCacheEntryCreateFailures, help
          entry_create_failures; 'mem_size'= some help string; 'entry_num'= some help
          string; 'replaced_entry'= some help string; 'aging_entry'= some help string;
          'cleaned_entry'= some help string; 'rsp_type_stream'= some help string;
          'header_save_error'= some help string;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hits:
                description:
                - "Cache hits"
                type: str
            miss:
                description:
                - "Cache misses"
                type: str
            bytes_served:
                description:
                - "Bytes served from cache"
                type: str
            total_req:
                description:
                - "Total requests received"
                type: str
            caching_req:
                description:
                - "Total requests to cache"
                type: str
            nc_req_header:
                description:
                - "slbTemplateCacheNcReqHeader, help nc_req_header"
                type: str
            nc_res_header:
                description:
                - "slbTemplateCacheNcResHeader, help nc_res_header"
                type: str
            rv_success:
                description:
                - "some help string"
                type: str
            rv_failure:
                description:
                - "slbTemplateCacheRvFailure, help rv_failure"
                type: str
            ims_request:
                description:
                - "some help string"
                type: str
            nm_response:
                description:
                - "some help string"
                type: str
            rsp_type_CL:
                description:
                - "some help string"
                type: str
            rsp_type_CE:
                description:
                - "some help string"
                type: str
            rsp_type_304:
                description:
                - "some help string"
                type: str
            rsp_type_other:
                description:
                - "some help string"
                type: str
            rsp_no_compress:
                description:
                - "some help string"
                type: str
            rsp_gzip:
                description:
                - "some help string"
                type: str
            rsp_deflate:
                description:
                - "some help string"
                type: str
            rsp_other:
                description:
                - "some help string"
                type: str
            nocache_match:
                description:
                - "some help string"
                type: str
            match:
                description:
                - "some help string"
                type: str
            invalidate_match:
                description:
                - "some help string"
                type: str
            content_toobig:
                description:
                - "slbTemplateCacheContentToobig, help content_toobig"
                type: str
            content_toosmall:
                description:
                - "slbTemplateCacheContentToosmall, help content_toosmall"
                type: str
            entry_create_failures:
                description:
                - "slbTemplateCacheEntryCreateFailures, help entry_create_failures"
                type: str
            mem_size:
                description:
                - "some help string"
                type: str
            entry_num:
                description:
                - "some help string"
                type: str
            replaced_entry:
                description:
                - "some help string"
                type: str
            aging_entry:
                description:
                - "some help string"
                type: str
            cleaned_entry:
                description:
                - "some help string"
                type: str
            rsp_type_stream:
                description:
                - "some help string"
                type: str
            header_save_error:
                description:
                - "some help string"
                type: str
            name:
                description:
                - "Specify cache template name"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "accept_reload_req", "age", "default_policy_nocache", "disable_insert_age", "disable_insert_via", "local_uri_policy", "logging", "max_cache_size", "max_content_size", "min_content_size", "name", "packet_capture_template", "remove_cookies", "replacement_policy", "sampling_enable", "stats", "uri_policy", "user_tag", "uuid", "verify_host",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
            },
        'accept_reload_req': {
            'type': 'bool',
            },
        'age': {
            'type': 'int',
            },
        'default_policy_nocache': {
            'type': 'bool',
            },
        'disable_insert_age': {
            'type': 'bool',
            },
        'disable_insert_via': {
            'type': 'bool',
            },
        'max_cache_size': {
            'type': 'int',
            },
        'min_content_size': {
            'type': 'int',
            },
        'max_content_size': {
            'type': 'int',
            },
        'local_uri_policy': {
            'type': 'list',
            'local_uri': {
                'type': 'str',
                }
            },
        'uri_policy': {
            'type': 'list',
            'uri': {
                'type': 'str',
                },
            'cache_action': {
                'type': 'str',
                'choices': ['cache', 'nocache']
                },
            'cache_value': {
                'type': 'int',
                },
            'invalidate': {
                'type': 'str',
                }
            },
        'remove_cookies': {
            'type': 'bool',
            },
        'replacement_policy': {
            'type': 'str',
            'choices': ['LFU']
            },
        'logging': {
            'type': 'str',
            },
        'verify_host': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'hits', 'miss', 'bytes_served', 'total_req', 'caching_req', 'nc_req_header', 'nc_res_header', 'rv_success', 'rv_failure', 'ims_request', 'nm_response', 'rsp_type_CL', 'rsp_type_CE', 'rsp_type_304', 'rsp_type_other', 'rsp_no_compress', 'rsp_gzip', 'rsp_deflate', 'rsp_other', 'nocache_match', 'match', 'invalidate_match',
                    'content_toobig', 'content_toosmall', 'entry_create_failures', 'mem_size', 'entry_num', 'replaced_entry', 'aging_entry', 'cleaned_entry', 'rsp_type_stream', 'header_save_error'
                    ]
                }
            },
        'packet_capture_template': {
            'type': 'str',
            },
        'stats': {
            'type': 'dict',
            'hits': {
                'type': 'str',
                },
            'miss': {
                'type': 'str',
                },
            'bytes_served': {
                'type': 'str',
                },
            'total_req': {
                'type': 'str',
                },
            'caching_req': {
                'type': 'str',
                },
            'nc_req_header': {
                'type': 'str',
                },
            'nc_res_header': {
                'type': 'str',
                },
            'rv_success': {
                'type': 'str',
                },
            'rv_failure': {
                'type': 'str',
                },
            'ims_request': {
                'type': 'str',
                },
            'nm_response': {
                'type': 'str',
                },
            'rsp_type_CL': {
                'type': 'str',
                },
            'rsp_type_CE': {
                'type': 'str',
                },
            'rsp_type_304': {
                'type': 'str',
                },
            'rsp_type_other': {
                'type': 'str',
                },
            'rsp_no_compress': {
                'type': 'str',
                },
            'rsp_gzip': {
                'type': 'str',
                },
            'rsp_deflate': {
                'type': 'str',
                },
            'rsp_other': {
                'type': 'str',
                },
            'nocache_match': {
                'type': 'str',
                },
            'match': {
                'type': 'str',
                },
            'invalidate_match': {
                'type': 'str',
                },
            'content_toobig': {
                'type': 'str',
                },
            'content_toosmall': {
                'type': 'str',
                },
            'entry_create_failures': {
                'type': 'str',
                },
            'mem_size': {
                'type': 'str',
                },
            'entry_num': {
                'type': 'str',
                },
            'replaced_entry': {
                'type': 'str',
                },
            'aging_entry': {
                'type': 'str',
                },
            'cleaned_entry': {
                'type': 'str',
                },
            'rsp_type_stream': {
                'type': 'str',
                },
            'header_save_error': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/cache/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["cache"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["cache"].get(k) != v:
            change_results["changed"] = True
            config_changes["cache"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("cache", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["cache"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["cache-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["cache"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
