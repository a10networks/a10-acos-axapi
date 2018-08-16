#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_waf_global
description:
    - None
short_description: Configures A10 waf.global
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    uuid:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_req','req_allowed','req_denied','bot_check_succ','bot_check_fail','form_consistency_succ','form_consistency_fail','form_csrf_tag_succ','form_csrf_tag_fail','url_check_succ','url_check_fail','url_check_learn','buf_ovf_url_len_fail','buf_ovf_cookie_len_fail','buf_ovf_hdrs_len_fail','buf_ovf_post_size_fail','max_cookies_fail','max_hdrs_fail','http_method_check_succ','http_method_check_fail','http_check_succ','http_check_fail','referer_check_succ','referer_check_fail','referer_check_redirect','uri_wlist_succ','uri_wlist_fail','uri_blist_succ','uri_blist_fail','post_form_check_succ','post_form_check_sanitize','post_form_check_reject','ccn_mask_amex','ccn_mask_diners','ccn_mask_visa','ccn_mask_mastercard','ccn_mask_discover','ccn_mask_jcb','ssn_mask','pcre_mask','cookie_encrypt_succ','cookie_encrypt_fail','cookie_encrypt_limit_exceeded','cookie_encrypt_skip_rcache','cookie_decrypt_succ','cookie_decrypt_fail','sqlia_chk_url_succ','sqlia_chk_url_sanitize','sqlia_chk_url_reject','sqlia_chk_post_succ','sqlia_chk_post_sanitize','sqlia_chk_post_reject','xss_chk_cookie_succ','xss_chk_cookie_sanitize','xss_chk_cookie_reject','xss_chk_url_succ','xss_chk_url_sanitize','xss_chk_url_reject','xss_chk_post_succ','xss_chk_post_sanitize','xss_chk_post_reject','resp_code_hidden','resp_hdrs_filtered','learn_updates','num_drops','num_resets','form_non_ssl_reject','form_non_post_reject','sess_check_none','sess_check_succ','sess_check_fail','soap_check_succ','soap_check_failure','wsdl_fail','wsdl_succ','xml_schema_fail','xml_schema_succ','xml_sqlia_chk_fail','xml_sqlia_chk_succ','xml_xss_chk_fail','xml_xss_chk_succ','json_check_failure','json_check_succ','xml_check_failure','xml_check_succ','buf_ovf_cookie_value_len_fail','buf_ovf_cookies_len_fail','buf_ovf_hdr_name_len_fail','buf_ovf_hdr_value_len_fail','buf_ovf_max_data_parse_fail','buf_ovf_line_len_fail','buf_ovf_parameter_name_len_fail','buf_ovf_parameter_value_len_fail','buf_ovf_parameter_total_len_fail','buf_ovf_query_len_fail','max_entities_fail','max_parameters_fail','buf_ovf_cookie_name_len_fail','xml_limit_attr','xml_limit_attr_name_len','xml_limit_attr_value_len','xml_limit_cdata_len','xml_limit_elem','xml_limit_elem_child','xml_limit_elem_depth','xml_limit_elem_name_len','xml_limit_entity_exp','xml_limit_entity_exp_depth','xml_limit_namespace','xml_limit_namespace_uri_len','json_limit_array_value_count','json_limit_depth','json_limit_object_member_count','json_limit_string','form_non_masked_password','form_non_ssl_password','form_password_autocomplete','redirect_wlist_succ','redirect_wlist_fail','redirect_wlist_learn','form_set_no_cache','resp_denied','sessions_alloc','sessions_freed','out_of_sessions','too_many_sessions','called','permitted','brute_force_success','brute_force_fail','challenge_cookie_sent','challenge_javascript_sent','challenge_captcha_sent'])),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/global"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/global"
    f_dict = {}

    return url_base.format(**f_dict)


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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("global", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
    payload = build_json("global", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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