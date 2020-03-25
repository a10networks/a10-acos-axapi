#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_ssl_cert_revoke
description:
    - Show ssl-cert-revoke-stats
short_description: Configures A10 slb.ssl-cert-revoke
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'ocsp_stapling_response_good'= OCSP stapling response good; 'ocsp_chain_status_good'= Certificate chain status good; 'ocsp_chain_status_revoked'= Certificate chain status revoked; 'ocsp_chain_status_unknown'= Certificate chain status unknown; 'ocsp_request'= OCSP requests; 'ocsp_response'= OCSP responses; 'ocsp_connection_error'= OCSP connection error; 'ocsp_uri_not_found'= OCSP URI not found; 'ocsp_uri_https'= Log OCSP URI https; 'ocsp_uri_unsupported'= OCSP URI unsupported; 'ocsp_response_status_good'= OCSP response status good; 'ocsp_response_status_revoked'= OCSP response status revoked; 'ocsp_response_status_unknown'= OCSP response status unknown; 'ocsp_cache_status_good'= OCSP cache status good; 'ocsp_cache_status_revoked'= OCSP cache status revoked; 'ocsp_cache_miss'= OCSP cache miss; 'ocsp_cache_expired'= OCSP cache expired; 'ocsp_other_error'= Log OCSP other errors; 'ocsp_response_no_nonce'= Log OCSP other errors; 'ocsp_response_nonce_error'= Log OCSP other errors; 'crl_request'= CRL requests; 'crl_response'= CRL responses; 'crl_connection_error'= CRL connection errors; 'crl_uri_not_found'= CRL URI not found; 'crl_uri_https'= CRL URI https; 'crl_uri_unsupported'= CRL URI unsupported; 'crl_response_status_good'= CRL response status good; 'crl_response_status_revoked'= CRL response status revoked; 'crl_response_status_unknown'= CRL response status unknown; 'crl_cache_status_good'= CRL cache status good; 'crl_cache_status_revoked'= CRL cache status revoked; 'crl_other_error'= CRL other errors; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            ocsp_request:
                description:
                - "OCSP requests"
            ocsp_cache_status_revoked:
                description:
                - "OCSP cache status revoked"
            crl_uri_not_found:
                description:
                - "CRL URI not found"
            ocsp_connection_error:
                description:
                - "OCSP connection error"
            ocsp_response_status_revoked:
                description:
                - "OCSP response status revoked"
            ocsp_chain_status_good:
                description:
                - "Certificate chain status good"
            ocsp_response_no_nonce:
                description:
                - "Log OCSP other errors"
            crl_response:
                description:
                - "CRL responses"
            crl_cache_status_good:
                description:
                - "CRL cache status good"
            ocsp_cache_expired:
                description:
                - "OCSP cache expired"
            ocsp_response_nonce_error:
                description:
                - "Log OCSP other errors"
            ocsp_uri_unsupported:
                description:
                - "OCSP URI unsupported"
            crl_other_error:
                description:
                - "CRL other errors"
            ocsp_cache_miss:
                description:
                - "OCSP cache miss"
            ocsp_stapling_response_good:
                description:
                - "OCSP stapling response good"
            ocsp_uri_https:
                description:
                - "Log OCSP URI https"
            crl_uri_https:
                description:
                - "CRL URI https"
            ocsp_chain_status_revoked:
                description:
                - "Certificate chain status revoked"
            ocsp_chain_status_unknown:
                description:
                - "Certificate chain status unknown"
            ocsp_uri_not_found:
                description:
                - "OCSP URI not found"
            crl_response_status_revoked:
                description:
                - "CRL response status revoked"
            crl_connection_error:
                description:
                - "CRL connection errors"
            ocsp_response_status_good:
                description:
                - "OCSP response status good"
            ocsp_response:
                description:
                - "OCSP responses"
            crl_response_status_unknown:
                description:
                - "CRL response status unknown"
            crl_uri_unsupported:
                description:
                - "CRL URI unsupported"
            ocsp_cache_status_good:
                description:
                - "OCSP cache status good"
            crl_request:
                description:
                - "CRL requests"
            ocsp_other_error:
                description:
                - "Log OCSP other errors"
            crl_response_status_good:
                description:
                - "CRL response status good"
            crl_cache_status_revoked:
                description:
                - "CRL cache status revoked"
            ocsp_response_status_unknown:
                description:
                - "OCSP response status unknown"
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
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','ocsp_stapling_response_good','ocsp_chain_status_good','ocsp_chain_status_revoked','ocsp_chain_status_unknown','ocsp_request','ocsp_response','ocsp_connection_error','ocsp_uri_not_found','ocsp_uri_https','ocsp_uri_unsupported','ocsp_response_status_good','ocsp_response_status_revoked','ocsp_response_status_unknown','ocsp_cache_status_good','ocsp_cache_status_revoked','ocsp_cache_miss','ocsp_cache_expired','ocsp_other_error','ocsp_response_no_nonce','ocsp_response_nonce_error','crl_request','crl_response','crl_connection_error','crl_uri_not_found','crl_uri_https','crl_uri_unsupported','crl_response_status_good','crl_response_status_revoked','crl_response_status_unknown','crl_cache_status_good','crl_cache_status_revoked','crl_other_error'])),
        stats=dict(type='dict',ocsp_request=dict(type='str',),ocsp_cache_status_revoked=dict(type='str',),crl_uri_not_found=dict(type='str',),ocsp_connection_error=dict(type='str',),ocsp_response_status_revoked=dict(type='str',),ocsp_chain_status_good=dict(type='str',),ocsp_response_no_nonce=dict(type='str',),crl_response=dict(type='str',),crl_cache_status_good=dict(type='str',),ocsp_cache_expired=dict(type='str',),ocsp_response_nonce_error=dict(type='str',),ocsp_uri_unsupported=dict(type='str',),crl_other_error=dict(type='str',),ocsp_cache_miss=dict(type='str',),ocsp_stapling_response_good=dict(type='str',),ocsp_uri_https=dict(type='str',),crl_uri_https=dict(type='str',),ocsp_chain_status_revoked=dict(type='str',),ocsp_chain_status_unknown=dict(type='str',),ocsp_uri_not_found=dict(type='str',),crl_response_status_revoked=dict(type='str',),crl_connection_error=dict(type='str',),ocsp_response_status_good=dict(type='str',),ocsp_response=dict(type='str',),crl_response_status_unknown=dict(type='str',),crl_uri_unsupported=dict(type='str',),ocsp_cache_status_good=dict(type='str',),crl_request=dict(type='str',),ocsp_other_error=dict(type='str',),crl_response_status_good=dict(type='str',),crl_cache_status_revoked=dict(type='str',),ocsp_response_status_unknown=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

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
        for k, v in payload["ssl-cert-revoke"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ssl-cert-revoke"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ssl-cert-revoke"][k] = v
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
    payload = build_json("ssl-cert-revoke", module)
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