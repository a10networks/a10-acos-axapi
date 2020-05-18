#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_server_ldap
description:
    - LDAP Authentication Server
short_description: Configures A10 aam.authentication.server.ldap
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            ldaps_server_list:
                description:
                - "Field ldaps_server_list"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'admin-bind-success'= Total Admin Bind Success; 'admin-bind-failure'= Total Admin Bind Failure; 'bind-success'= Total User Bind Success; 'bind-failure'= Total User Bind Failure; 'search-success'= Total Search Success; 'search-failure'= Total Search Failure; 'authorize-success'= Total Authorization Success; 'authorize-failure'= Total Authorization Failure; 'timeout-error'= Total Timeout; 'other-error'= Total Other Error; 'request'= Total Request; 'request-normal'= Total Normal Request; 'request-dropped'= Total Dropped Request; 'response-success'= Total Success Response; 'response-failure'= Total Failure Response; 'response-error'= Total Error Response; 'response-timeout'= Total Timeout Response; 'response-other'= Total Other Response; 'job-start-error'= Total Job Start Error; 'polling-control-error'= Total Polling Control Error; 'ssl-session-created'= TLS/SSL Session Created; 'ssl-session-failure'= TLS/SSL Session Failure; 'ldaps-idle-conn-num'= LDAPS Idle Connection Number; 'ldaps-inuse-conn-num'= LDAPS In-use Connection Number; 'pw-expiry'= Total Password expiry; 'pw-change-success'= Total password change success; 'pw-change-failure'= Total password change failure; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            pw_change_success:
                description:
                - "Total password change success"
            admin_bind_success:
                description:
                - "Total Admin Bind Success"
            response_failure:
                description:
                - "Total Failure Response"
            request_dropped:
                description:
                - "Total Dropped Request"
            other_error:
                description:
                - "Total Other Error"
            response_timeout:
                description:
                - "Total Timeout Response"
            job_start_error:
                description:
                - "Total Job Start Error"
            search_failure:
                description:
                - "Total Search Failure"
            bind_failure:
                description:
                - "Total User Bind Failure"
            request_normal:
                description:
                - "Total Normal Request"
            instance_list:
                description:
                - "Field instance_list"
            response_other:
                description:
                - "Total Other Response"
            pw_change_failure:
                description:
                - "Total password change failure"
            timeout_error:
                description:
                - "Total Timeout"
            ldaps_idle_conn_num:
                description:
                - "LDAPS Idle Connection Number"
            ssl_session_failure:
                description:
                - "TLS/SSL Session Failure"
            authorize_failure:
                description:
                - "Total Authorization Failure"
            ldaps_inuse_conn_num:
                description:
                - "LDAPS In-use Connection Number"
            search_success:
                description:
                - "Total Search Success"
            ssl_session_created:
                description:
                - "TLS/SSL Session Created"
            bind_success:
                description:
                - "Total User Bind Success"
            admin_bind_failure:
                description:
                - "Total Admin Bind Failure"
            authorize_success:
                description:
                - "Total Authorization Success"
            request:
                description:
                - "Total Request"
            polling_control_error:
                description:
                - "Total Polling Control Error"
            pw_expiry:
                description:
                - "Total Password expiry"
            response_success:
                description:
                - "Total Success Response"
            response_error:
                description:
                - "Total Error Response"
    uuid:
        description:
        - "uuid of the object"
        required: False
    instance_list:
        description:
        - "Field instance_list"
        required: False
        suboptions:
            health_check_disable:
                description:
                - "Disable configured health check configuration"
            protocol:
                description:
                - "'ldap'= Use LDAP (default); 'ldaps'= Use LDAP over SSL; 'starttls'= Use LDAP StartTLS; "
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)"
            port:
                description:
                - "Specify the LDAP server's authentication port, default is 389"
            ldaps_conn_reuse_idle_timeout:
                description:
                - "Specify LDAPS connection reuse idle timeout value (in seconds) (Specify idle timeout value (in seconds), default is 0 (not reuse LDAPS connection))"
            port_hm:
                description:
                - "Check port's health status"
            uuid:
                description:
                - "uuid of the object"
            admin_dn:
                description:
                - "The LDAP server's admin DN"
            default_domain:
                description:
                - "Specify default domain for LDAP"
            auth_type:
                description:
                - "'ad'= Active Directory. Default; 'open-ldap'= OpenLDAP; "
            admin_secret:
                description:
                - "Specify the LDAP server's admin secret password"
            pwdmaxage:
                description:
                - "Specify the LDAP server's default password expiration time (in seconds) (The LDAP server's default password expiration time (in seconds), default is 0 (no expiration))"
            health_check_string:
                description:
                - "Health monitor name"
            derive_bind_dn:
                description:
                - "Field derive_bind_dn"
            prompt_pw_change_before_exp:
                description:
                - "Prompt user to change password before expiration in N days. This option only takes effect when server type is AD (Prompt user to change password before expiration in N days, default is not to prompt the user)"
            base:
                description:
                - "Specify the LDAP server's search base"
            secret_string:
                description:
                - "secret password"
            name:
                description:
                - "Specify LDAP authentication server name"
            port_hm_disable:
                description:
                - "Disable configured port health check configuration"
            host:
                description:
                - "Field host"
            ca_cert:
                description:
                - "Specify the LDAPS CA cert filename (Trusted LDAPS CA cert filename)"
            bind_with_dn:
                description:
                - "Enforce using DN for LDAP binding(All user input name will be used to create DN)"
            sampling_enable:
                description:
                - "Field sampling_enable"
            dn_attribute:
                description:
                - "Specify Distinguished Name attribute, default is CN"
            timeout:
                description:
                - "Specify timout for LDAP, default is 10 seconds (The timeout, default is 10 seconds)"
            health_check:
                description:
                - "Check server's health status"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["instance_list","oper","sampling_enable","stats","uuid",]

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
        oper=dict(type='dict', ldaps_server_list=dict(type='list', ldaps_idle_conn_num=dict(type='int', ), ldaps_inuse_conn_num=dict(type='int', ), ldaps_inuse_conn_fd_list=dict(type='str', ), ldaps_idle_conn_fd_list=dict(type='str', ), ldap_uri=dict(type='str', ))),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'admin-bind-success', 'admin-bind-failure', 'bind-success', 'bind-failure', 'search-success', 'search-failure', 'authorize-success', 'authorize-failure', 'timeout-error', 'other-error', 'request', 'request-normal', 'request-dropped', 'response-success', 'response-failure', 'response-error', 'response-timeout', 'response-other', 'job-start-error', 'polling-control-error', 'ssl-session-created', 'ssl-session-failure', 'ldaps-idle-conn-num', 'ldaps-inuse-conn-num', 'pw-expiry', 'pw-change-success', 'pw-change-failure'])),
        stats=dict(type='dict', pw_change_success=dict(type='str', ), admin_bind_success=dict(type='str', ), response_failure=dict(type='str', ), request_dropped=dict(type='str', ), other_error=dict(type='str', ), response_timeout=dict(type='str', ), job_start_error=dict(type='str', ), search_failure=dict(type='str', ), bind_failure=dict(type='str', ), request_normal=dict(type='str', ), instance_list=dict(type='list', stats=dict(type='dict', bind_failure=dict(type='str', ), authorize_failure=dict(type='str', ), admin_bind_failure=dict(type='str', ), search_failure=dict(type='str', ), authorize_success=dict(type='str', ), pw_change_success=dict(type='str', ), timeout_error=dict(type='str', ), request=dict(type='str', ), pw_expiry=dict(type='str', ), admin_bind_success=dict(type='str', ), search_success=dict(type='str', ), other_error=dict(type='str', ), ssl_session_created=dict(type='str', ), pw_change_failure=dict(type='str', ), ssl_session_failure=dict(type='str', ), bind_success=dict(type='str', )), name=dict(type='str', required=True, )), response_other=dict(type='str', ), pw_change_failure=dict(type='str', ), timeout_error=dict(type='str', ), ldaps_idle_conn_num=dict(type='str', ), ssl_session_failure=dict(type='str', ), authorize_failure=dict(type='str', ), ldaps_inuse_conn_num=dict(type='str', ), search_success=dict(type='str', ), ssl_session_created=dict(type='str', ), bind_success=dict(type='str', ), admin_bind_failure=dict(type='str', ), authorize_success=dict(type='str', ), request=dict(type='str', ), polling_control_error=dict(type='str', ), pw_expiry=dict(type='str', ), response_success=dict(type='str', ), response_error=dict(type='str', )),
        uuid=dict(type='str', ),
        instance_list=dict(type='list', health_check_disable=dict(type='bool', ), protocol=dict(type='str', choices=['ldap', 'ldaps', 'starttls']), encrypted=dict(type='str', ), port=dict(type='int', ), ldaps_conn_reuse_idle_timeout=dict(type='int', ), port_hm=dict(type='str', ), uuid=dict(type='str', ), admin_dn=dict(type='str', ), default_domain=dict(type='str', ), auth_type=dict(type='str', choices=['ad', 'open-ldap']), admin_secret=dict(type='bool', ), pwdmaxage=dict(type='int', ), health_check_string=dict(type='str', ), derive_bind_dn=dict(type='dict', username_attr=dict(type='str', )), prompt_pw_change_before_exp=dict(type='int', ), base=dict(type='str', ), secret_string=dict(type='str', ), name=dict(type='str', required=True, ), port_hm_disable=dict(type='bool', ), host=dict(type='dict', hostipv6=dict(type='str', ), hostip=dict(type='str', )), ca_cert=dict(type='str', ), bind_with_dn=dict(type='bool', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'admin-bind-success', 'admin-bind-failure', 'bind-success', 'bind-failure', 'search-success', 'search-failure', 'authorize-success', 'authorize-failure', 'timeout-error', 'other-error', 'request', 'ssl-session-created', 'ssl-session-failure', 'pw_expiry', 'pw_change_success', 'pw_change_failure'])), dn_attribute=dict(type='str', ), timeout=dict(type='int', ), health_check=dict(type='bool', ))
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/ldap"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

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
    url_base = "/axapi/v3/aam/authentication/server/ldap"

    f_dict = {}

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
        for k, v in payload["ldap"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ldap"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ldap"][k] = v
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
    payload = build_json("ldap", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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