#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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

"""

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        stats=dict(type='dict',waf=dict(type='dict',redirect_wlist_fail=dict(type='str',),cookie_encrypt_limit_exceeded=dict(type='str',),wsdl_succ=dict(type='str',),sqlia_chk_url_succ=dict(type='str',),bot_check_succ=dict(type='str',),cookie_encrypt_skip_rcache=dict(type='str',),redirect_wlist_learn=dict(type='str',),xml_limit_elem_child=dict(type='str',),buf_ovf_parameter_value_len_fail=dict(type='str',),ccn_mask_visa=dict(type='str',),xss_chk_cookie_succ=dict(type='str',),buf_ovf_cookies_len_fail=dict(type='str',),req_denied=dict(type='str',),json_check_failure=dict(type='str',),xss_chk_post_reject=dict(type='str',),http_check_succ=dict(type='str',),form_consistency_succ=dict(type='str',),xml_limit_cdata_len=dict(type='str',),xml_check_failure=dict(type='str',),buf_ovf_hdrs_len_fail=dict(type='str',),referer_check_succ=dict(type='str',),sqlia_chk_post_succ=dict(type='str',),xss_chk_url_sanitize=dict(type='str',),cookie_encrypt_succ=dict(type='str',),buf_ovf_parameter_total_len_fail=dict(type='str',),soap_check_succ=dict(type='str',),max_cookies_fail=dict(type='str',),json_limit_array_value_count=dict(type='str',),uri_wlist_succ=dict(type='str',),brute_force_success=dict(type='str',),resp_code_hidden=dict(type='str',),xml_sqlia_chk_fail=dict(type='str',),xss_chk_post_succ=dict(type='str',),pcre_mask=dict(type='str',),form_consistency_fail=dict(type='str',),http_check_fail=dict(type='str',),url_check_succ=dict(type='str',),sqlia_chk_url_reject=dict(type='str',),sqlia_chk_url_sanitize=dict(type='str',),xss_chk_cookie_reject=dict(type='str',),json_check_succ=dict(type='str',),max_entities_fail=dict(type='str',),http_method_check_fail=dict(type='str',),form_non_ssl_reject=dict(type='str',),xss_chk_post_sanitize=dict(type='str',),form_set_no_cache=dict(type='str',),xml_schema_succ=dict(type='str',),xml_limit_attr=dict(type='str',),xml_check_succ=dict(type='str',),sess_check_none=dict(type='str',),xml_limit_namespace=dict(type='str',),wsdl_fail=dict(type='str',),post_form_check_succ=dict(type='str',),buf_ovf_query_len_fail=dict(type='str',),sqlia_chk_post_reject=dict(type='str',),form_password_autocomplete=dict(type='str',),permitted=dict(type='str',),xml_xss_chk_fail=dict(type='str',),buf_ovf_url_len_fail=dict(type='str',),buf_ovf_cookie_len_fail=dict(type='str',),form_csrf_tag_succ=dict(type='str',),xss_chk_cookie_sanitize=dict(type='str',),sessions_alloc=dict(type='str',),xml_limit_entity_exp=dict(type='str',),ccn_mask_diners=dict(type='str',),sess_check_succ=dict(type='str',),json_limit_depth=dict(type='str',),buf_ovf_cookie_name_len_fail=dict(type='str',),learn_updates=dict(type='str',),redirect_wlist_succ=dict(type='str',),challenge_javascript_sent=dict(type='str',),req_allowed=dict(type='str',),json_limit_object_member_count=dict(type='str',),bot_check_fail=dict(type='str',),uri_wlist_fail=dict(type='str',),uri_blist_fail=dict(type='str',),referer_check_redirect=dict(type='str',),challenge_cookie_sent=dict(type='str',),sqlia_chk_post_sanitize=dict(type='str',),ccn_mask_amex=dict(type='str',),num_drops=dict(type='str',),referer_check_fail=dict(type='str',),post_form_check_sanitize=dict(type='str',),cookie_decrypt_succ=dict(type='str',),xss_chk_url_reject=dict(type='str',),max_parameters_fail=dict(type='str',),url_check_fail=dict(type='str',),xml_schema_fail=dict(type='str',),form_non_post_reject=dict(type='str',),num_resets=dict(type='str',),xml_limit_entity_exp_depth=dict(type='str',),form_non_masked_password=dict(type='str',),buf_ovf_line_len_fail=dict(type='str',),ccn_mask_discover=dict(type='str',),ssn_mask=dict(type='str',),json_limit_string=dict(type='str',),resp_hdrs_filtered=dict(type='str',),called=dict(type='str',),ccn_mask_mastercard=dict(type='str',),xml_sqlia_chk_succ=dict(type='str',),brute_force_fail=dict(type='str',),max_hdrs_fail=dict(type='str',),xml_limit_attr_name_len=dict(type='str',),form_non_ssl_password=dict(type='str',),too_many_sessions=dict(type='str',),buf_ovf_hdr_value_len_fail=dict(type='str',),uri_blist_succ=dict(type='str',),sess_check_fail=dict(type='str',),buf_ovf_hdr_name_len_fail=dict(type='str',),resp_denied=dict(type='str',),sessions_freed=dict(type='str',),out_of_sessions=dict(type='str',),xml_limit_elem=dict(type='str',),buf_ovf_parameter_name_len_fail=dict(type='str',),xml_limit_attr_value_len=dict(type='str',),xml_limit_elem_depth=dict(type='str',),ccn_mask_jcb=dict(type='str',),cookie_decrypt_fail=dict(type='str',),buf_ovf_cookie_value_len_fail=dict(type='str',),buf_ovf_post_size_fail=dict(type='str',),total_req=dict(type='str',),xml_limit_elem_name_len=dict(type='str',),url_check_learn=dict(type='str',),http_method_check_succ=dict(type='str',),xss_chk_url_succ=dict(type='str',),xml_limit_namespace_uri_len=dict(type='str',),post_form_check_reject=dict(type='str',),cookie_encrypt_fail=dict(type='str',),soap_check_failure=dict(type='str',),challenge_captcha_sent=dict(type='str',),form_csrf_tag_fail=dict(type='str',),xml_xss_chk_succ=dict(type='str',),buf_ovf_max_data_parse_fail=dict(type='str',))),
        name=dict(type='str',required=True,)
    ))
   
    # Parent keys
    rv.update(dict(
        protocol=dict(type='str', required=True),
        port_number=dict(type='str', required=True),
        virtual_server_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("port", module)
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
    payload = build_json("port", module)
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
    payload = build_json("port", module)
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
        message=""
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
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
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