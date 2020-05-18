#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_virtual_server_port_stats_waf
description:
    - Statistics for the object port
short_description: Configures A10 slb.virtual-server.port.stats.waf
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
    protocol:
        description:
        - Key to identify parent object
    port_number:
        description:
        - Key to identify parent object
    virtual_server_name:
        description:
        - Key to identify parent object
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            waf:
                description:
                - "Field waf"
    name:
        description:
        - "WAF Template Name"
        required: True


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["name","stats",]

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
        stats=dict(type='dict', waf=dict(type='dict', redirect_wlist_fail=dict(type='str', ), cookie_encrypt_limit_exceeded=dict(type='str', ), wsdl_succ=dict(type='str', ), sqlia_chk_url_succ=dict(type='str', ), bot_check_succ=dict(type='str', ), cookie_encrypt_skip_rcache=dict(type='str', ), redirect_wlist_learn=dict(type='str', ), xml_limit_elem_child=dict(type='str', ), buf_ovf_parameter_value_len_fail=dict(type='str', ), ccn_mask_visa=dict(type='str', ), xss_chk_cookie_succ=dict(type='str', ), buf_ovf_cookies_len_fail=dict(type='str', ), req_denied=dict(type='str', ), json_check_failure=dict(type='str', ), xss_chk_post_reject=dict(type='str', ), http_check_succ=dict(type='str', ), form_consistency_succ=dict(type='str', ), xml_limit_cdata_len=dict(type='str', ), xml_check_failure=dict(type='str', ), buf_ovf_hdrs_len_fail=dict(type='str', ), referer_check_succ=dict(type='str', ), sqlia_chk_post_succ=dict(type='str', ), xss_chk_url_sanitize=dict(type='str', ), cookie_encrypt_succ=dict(type='str', ), buf_ovf_parameter_total_len_fail=dict(type='str', ), soap_check_succ=dict(type='str', ), max_cookies_fail=dict(type='str', ), json_limit_array_value_count=dict(type='str', ), uri_wlist_succ=dict(type='str', ), brute_force_success=dict(type='str', ), resp_code_hidden=dict(type='str', ), xml_sqlia_chk_fail=dict(type='str', ), xss_chk_post_succ=dict(type='str', ), pcre_mask=dict(type='str', ), form_consistency_fail=dict(type='str', ), http_check_fail=dict(type='str', ), url_check_succ=dict(type='str', ), sqlia_chk_url_reject=dict(type='str', ), sqlia_chk_url_sanitize=dict(type='str', ), xss_chk_cookie_reject=dict(type='str', ), json_check_succ=dict(type='str', ), max_entities_fail=dict(type='str', ), http_method_check_fail=dict(type='str', ), form_non_ssl_reject=dict(type='str', ), xss_chk_post_sanitize=dict(type='str', ), form_set_no_cache=dict(type='str', ), xml_schema_succ=dict(type='str', ), xml_limit_attr=dict(type='str', ), xml_check_succ=dict(type='str', ), sess_check_none=dict(type='str', ), xml_limit_namespace=dict(type='str', ), wsdl_fail=dict(type='str', ), post_form_check_succ=dict(type='str', ), buf_ovf_query_len_fail=dict(type='str', ), sqlia_chk_post_reject=dict(type='str', ), form_password_autocomplete=dict(type='str', ), permitted=dict(type='str', ), xml_xss_chk_fail=dict(type='str', ), buf_ovf_url_len_fail=dict(type='str', ), buf_ovf_cookie_len_fail=dict(type='str', ), form_csrf_tag_succ=dict(type='str', ), xss_chk_cookie_sanitize=dict(type='str', ), sessions_alloc=dict(type='str', ), xml_limit_entity_exp=dict(type='str', ), ccn_mask_diners=dict(type='str', ), sess_check_succ=dict(type='str', ), json_limit_depth=dict(type='str', ), buf_ovf_cookie_name_len_fail=dict(type='str', ), learn_updates=dict(type='str', ), redirect_wlist_succ=dict(type='str', ), challenge_javascript_sent=dict(type='str', ), req_allowed=dict(type='str', ), json_limit_object_member_count=dict(type='str', ), bot_check_fail=dict(type='str', ), uri_wlist_fail=dict(type='str', ), uri_blist_fail=dict(type='str', ), referer_check_redirect=dict(type='str', ), challenge_cookie_sent=dict(type='str', ), sqlia_chk_post_sanitize=dict(type='str', ), ccn_mask_amex=dict(type='str', ), num_drops=dict(type='str', ), referer_check_fail=dict(type='str', ), post_form_check_sanitize=dict(type='str', ), cookie_decrypt_succ=dict(type='str', ), xss_chk_url_reject=dict(type='str', ), max_parameters_fail=dict(type='str', ), url_check_fail=dict(type='str', ), xml_schema_fail=dict(type='str', ), form_non_post_reject=dict(type='str', ), num_resets=dict(type='str', ), xml_limit_entity_exp_depth=dict(type='str', ), form_non_masked_password=dict(type='str', ), buf_ovf_line_len_fail=dict(type='str', ), ccn_mask_discover=dict(type='str', ), ssn_mask=dict(type='str', ), json_limit_string=dict(type='str', ), resp_hdrs_filtered=dict(type='str', ), called=dict(type='str', ), ccn_mask_mastercard=dict(type='str', ), xml_sqlia_chk_succ=dict(type='str', ), brute_force_fail=dict(type='str', ), max_hdrs_fail=dict(type='str', ), xml_limit_attr_name_len=dict(type='str', ), form_non_ssl_password=dict(type='str', ), too_many_sessions=dict(type='str', ), buf_ovf_hdr_value_len_fail=dict(type='str', ), uri_blist_succ=dict(type='str', ), sess_check_fail=dict(type='str', ), buf_ovf_hdr_name_len_fail=dict(type='str', ), resp_denied=dict(type='str', ), sessions_freed=dict(type='str', ), out_of_sessions=dict(type='str', ), xml_limit_elem=dict(type='str', ), buf_ovf_parameter_name_len_fail=dict(type='str', ), xml_limit_attr_value_len=dict(type='str', ), xml_limit_elem_depth=dict(type='str', ), ccn_mask_jcb=dict(type='str', ), cookie_decrypt_fail=dict(type='str', ), buf_ovf_cookie_value_len_fail=dict(type='str', ), buf_ovf_post_size_fail=dict(type='str', ), total_req=dict(type='str', ), xml_limit_elem_name_len=dict(type='str', ), url_check_learn=dict(type='str', ), http_method_check_succ=dict(type='str', ), xss_chk_url_succ=dict(type='str', ), xml_limit_namespace_uri_len=dict(type='str', ), post_form_check_reject=dict(type='str', ), cookie_encrypt_fail=dict(type='str', ), soap_check_failure=dict(type='str', ), challenge_captcha_sent=dict(type='str', ), form_csrf_tag_fail=dict(type='str', ), xml_xss_chk_succ=dict(type='str', ), buf_ovf_max_data_parse_fail=dict(type='str', ))),
        name=dict(type='str', required=True, )
    ))
   
    # Parent keys
    rv.update(dict(
        protocol=dict(type='str', required=True),
        port_number=dict(type='str', required=True),
        virtual_server_name=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

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
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

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
        for k, v in payload["port"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["port"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["port"][k] = v
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
    payload = build_json("port", module)
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