#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_relay_ntlm
description:
    - NTLM Authentication Relay
short_description: Configures A10 aam.authentication.relay.ntlm
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
    domain:
        description:
        - "Specify NTLM domain, default is null"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            parse_header_fail:
                description:
                - "Parse Header Failure"
            ntlm_auth_skipped:
                description:
                - "Requests for which NTLM relay is skipped"
            head_negotiate_request_sent:
                description:
                - "HEAD requests sent with NEGOTIATE header"
            http_code_other:
                description:
                - "Other HTTP Response"
            internal_error:
                description:
                - "Internal Error"
            buffer_alloc_fail:
                description:
                - "Buffer Allocation Failure"
            failure:
                description:
                - "Failure"
            http_code_400:
                description:
                - "HTTP 400 Bad Request"
            http_code_401:
                description:
                - "HTTP 401 Unauthorized"
            http_code_403:
                description:
                - "HTTP 403 Forbidden"
            http_code_404:
                description:
                - "HTTP 404 Not Found"
            http_code_500:
                description:
                - "HTTP 500 Internal Server Error"
            http_code_503:
                description:
                - "HTTP 503 Service Unavailable"
            large_request_processing:
                description:
                - "Requests invoking large request processing"
            response:
                description:
                - "Response"
            head_auth_request_sent:
                description:
                - "HEAD requests sent with AUTH header"
            name:
                description:
                - "Specify NTLM authentication relay name"
            http_code_200:
                description:
                - "HTTP 200 OK"
            success:
                description:
                - "Success"
            encoding_fail:
                description:
                - "Encoding Failure"
            request:
                description:
                - "Request"
            large_request_flushed:
                description:
                - "Large requests sent to server"
            insert_header_fail:
                description:
                - "Insert Header Failure"
    name:
        description:
        - "Specify NTLM authentication relay name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'success'= Success; 'failure'= Failure; 'request'= Request; 'response'= Response; 'http-code-200'= HTTP 200 OK; 'http-code-400'= HTTP 400 Bad Request; 'http-code-401'= HTTP 401 Unauthorized; 'http-code-403'= HTTP 403 Forbidden; 'http-code-404'= HTTP 404 Not Found; 'http-code-500'= HTTP 500 Internal Server Error; 'http-code-503'= HTTP 503 Service Unavailable; 'http-code-other'= Other HTTP Response; 'buffer-alloc-fail'= Buffer Allocation Failure; 'encoding-fail'= Encoding Failure; 'insert-header-fail'= Insert Header Failure; 'parse-header-fail'= Parse Header Failure; 'internal-error'= Internal Error; 'ntlm-auth-skipped'= Requests for which NTLM relay is skipped; 'large-request-processing'= Requests invoking large request processing; 'large-request-flushed'= Large requests sent to server; 'head-negotiate-request-sent'= HEAD requests sent with NEGOTIATE header; 'head-auth-request-sent'= HEAD requests sent with AUTH header; "
    version:
        description:
        - "Specify NTLM version, default is NTLM 2"
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
AVAILABLE_PROPERTIES = ["domain","name","sampling_enable","stats","user_tag","uuid","version",]

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
        domain=dict(type='str',),
        stats=dict(type='dict',parse_header_fail=dict(type='str',),ntlm_auth_skipped=dict(type='str',),head_negotiate_request_sent=dict(type='str',),http_code_other=dict(type='str',),internal_error=dict(type='str',),buffer_alloc_fail=dict(type='str',),failure=dict(type='str',),http_code_400=dict(type='str',),http_code_401=dict(type='str',),http_code_403=dict(type='str',),http_code_404=dict(type='str',),http_code_500=dict(type='str',),http_code_503=dict(type='str',),large_request_processing=dict(type='str',),response=dict(type='str',),head_auth_request_sent=dict(type='str',),name=dict(type='str',required=True,),http_code_200=dict(type='str',),success=dict(type='str',),encoding_fail=dict(type='str',),request=dict(type='str',),large_request_flushed=dict(type='str',),insert_header_fail=dict(type='str',)),
        name=dict(type='str',required=True,),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','success','failure','request','response','http-code-200','http-code-400','http-code-401','http-code-403','http-code-404','http-code-500','http-code-503','http-code-other','buffer-alloc-fail','encoding-fail','insert-header-fail','parse-header-fail','internal-error','ntlm-auth-skipped','large-request-processing','large-request-flushed','head-negotiate-request-sent','head-auth-request-sent'])),
        version=dict(type='int',),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/relay/ntlm/{name}"

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
    url_base = "/axapi/v3/aam/authentication/relay/ntlm/{name}"

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
        for k, v in payload["ntlm"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ntlm"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ntlm"][k] = v
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
    payload = build_json("ntlm", module)
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