#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_server_windows
description:
    - 'Windows Server, using Kerberos or NTLM for authentication'
short_description: Configures A10 aam.authentication.server.windows
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
                - "'all'= all; 'kerberos-request-send'= Total Kerberos Request; 'kerberos-response-get'= Total Kerberos Response; 'kerberos-timeout-error'= Total Kerberos Timeout; 'kerberos-other-error'= Total Kerberos Other Error; 'ntlm-authentication-success'= Total NTLM Authentication Success; 'ntlm-authentication-failure'= Total NTLM Authentication Failure; 'ntlm-proto-negotiation-success'= Total NTLM Protocol Negotiation Success; 'ntlm-proto-negotiation-failure'= Total NTLM Protocol Negotiation Failure; 'ntlm-session-setup-success'= Total NTLM Session Setup Success; 'ntlm-session-setup-failed'= Total NTLM Session Setup Failure; 'kerberos-request-normal'= Total Kerberos Normal Request; 'kerberos-request-dropped'= Total Kerberos Dropped Request; 'kerberos-response-success'= Total Kerberos Success Response; 'kerberos-response-failure'= Total Kerberos Failure Response; 'kerberos-response-error'= Total Kerberos Error Response; 'kerberos-response-timeout'= Total Kerberos Timeout Response; 'kerberos-response-other'= Total Kerberos Other Response; 'kerberos-job-start-error'= Total Kerberos Job Start Error; 'kerberos-polling-control-error'= Total Kerberos Polling Control Error; 'ntlm-prepare-req-success'= Total NTLM Prepare Request Success; 'ntlm-prepare-req-failed'= Total NTLM Prepare Request Failed; 'ntlm-timeout-error'= Total NTLM Timeout; 'ntlm-other-error'= Total NTLM Other Error; 'ntlm-request-normal'= Total NTLM Normal Request; 'ntlm-request-dropped'= Total NTLM Dropped Request; 'ntlm-response-success'= Total NTLM Success Response; 'ntlm-response-failure'= Total NTLM Failure Response; 'ntlm-response-error'= Total NTLM Error Response; 'ntlm-response-timeout'= Total NTLM Timeout Response; 'ntlm-response-other'= Total NTLM Other Response; 'ntlm-job-start-error'= Total NTLM Job Start Error; 'ntlm-polling-control-error'= Total NTLM Polling Control Error; 'kerberos-pw-expiry'= Total Kerberos password expiry; 'kerberos-pw-change-success'= Total Kerberos password change success; 'kerberos-pw-change-failure'= Total Kerberos password change failure; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            kerberos_pw_change_success:
                description:
                - "Total Kerberos password change success"
            ntlm_response_error:
                description:
                - "Total NTLM Error Response"
            ntlm_session_setup_failed:
                description:
                - "Total NTLM Session Setup Failure"
            ntlm_polling_control_error:
                description:
                - "Total NTLM Polling Control Error"
            kerberos_other_error:
                description:
                - "Total Kerberos Other Error"
            kerberos_timeout_error:
                description:
                - "Total Kerberos Timeout"
            kerberos_job_start_error:
                description:
                - "Total Kerberos Job Start Error"
            ntlm_proto_negotiation_success:
                description:
                - "Total NTLM Protocol Negotiation Success"
            ntlm_other_error:
                description:
                - "Total NTLM Other Error"
            ntlm_job_start_error:
                description:
                - "Total NTLM Job Start Error"
            kerberos_response_failure:
                description:
                - "Total Kerberos Failure Response"
            ntlm_prepare_req_success:
                description:
                - "Total NTLM Prepare Request Success"
            ntlm_response_failure:
                description:
                - "Total NTLM Failure Response"
            kerberos_polling_control_error:
                description:
                - "Total Kerberos Polling Control Error"
            ntlm_prepare_req_failed:
                description:
                - "Total NTLM Prepare Request Failed"
            kerberos_response_success:
                description:
                - "Total Kerberos Success Response"
            kerberos_pw_expiry:
                description:
                - "Total Kerberos password expiry"
            ntlm_authentication_success:
                description:
                - "Total NTLM Authentication Success"
            ntlm_response_timeout:
                description:
                - "Total NTLM Timeout Response"
            ntlm_authentication_failure:
                description:
                - "Total NTLM Authentication Failure"
            kerberos_request_send:
                description:
                - "Total Kerberos Request"
            kerberos_pw_change_failure:
                description:
                - "Total Kerberos password change failure"
            kerberos_request_normal:
                description:
                - "Total Kerberos Normal Request"
            ntlm_response_other:
                description:
                - "Total NTLM Other Response"
            kerberos_request_dropped:
                description:
                - "Total Kerberos Dropped Request"
            kerberos_response_other:
                description:
                - "Total Kerberos Other Response"
            ntlm_session_setup_success:
                description:
                - "Total NTLM Session Setup Success"
            kerberos_response_error:
                description:
                - "Total Kerberos Error Response"
            ntlm_request_normal:
                description:
                - "Total NTLM Normal Request"
            ntlm_request_dropped:
                description:
                - "Total NTLM Dropped Request"
            instance_list:
                description:
                - "Field instance_list"
            kerberos_response_timeout:
                description:
                - "Total Kerberos Timeout Response"
            kerberos_response_get:
                description:
                - "Total Kerberos Response"
            ntlm_timeout_error:
                description:
                - "Total NTLM Timeout"
            ntlm_proto_negotiation_failure:
                description:
                - "Total NTLM Protocol Negotiation Failure"
            ntlm_response_success:
                description:
                - "Total NTLM Success Response"
    uuid:
        description:
        - "uuid of the object"
        required: False
    instance_list:
        description:
        - "Field instance_list"
        required: False
        suboptions:
            health_check_string:
                description:
                - "Health monitor name"
            realm:
                description:
                - "Specify realm of Windows server"
            name:
                description:
                - "Specify Windows authentication server name"
            sampling_enable:
                description:
                - "Field sampling_enable"
            host:
                description:
                - "Field host"
            timeout:
                description:
                - "Specify connection timeout to server, default is 10 seconds"
            auth_protocol:
                description:
                - "Field auth_protocol"
            health_check_disable:
                description:
                - "Disable configured health check configuration"
            support_apacheds_kdc:
                description:
                - "Enable weak cipher (DES CRC/MD5/MD4) and merge AS-REQ in single packet"
            health_check:
                description:
                - "Check server's health status"
            uuid:
                description:
                - "uuid of the object"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["instance_list","sampling_enable","stats","uuid",]

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
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','kerberos-request-send','kerberos-response-get','kerberos-timeout-error','kerberos-other-error','ntlm-authentication-success','ntlm-authentication-failure','ntlm-proto-negotiation-success','ntlm-proto-negotiation-failure','ntlm-session-setup-success','ntlm-session-setup-failed','kerberos-request-normal','kerberos-request-dropped','kerberos-response-success','kerberos-response-failure','kerberos-response-error','kerberos-response-timeout','kerberos-response-other','kerberos-job-start-error','kerberos-polling-control-error','ntlm-prepare-req-success','ntlm-prepare-req-failed','ntlm-timeout-error','ntlm-other-error','ntlm-request-normal','ntlm-request-dropped','ntlm-response-success','ntlm-response-failure','ntlm-response-error','ntlm-response-timeout','ntlm-response-other','ntlm-job-start-error','ntlm-polling-control-error','kerberos-pw-expiry','kerberos-pw-change-success','kerberos-pw-change-failure'])),
        stats=dict(type='dict', kerberos_pw_change_success=dict(type='str', ),ntlm_response_error=dict(type='str', ),ntlm_session_setup_failed=dict(type='str', ),ntlm_polling_control_error=dict(type='str', ),kerberos_other_error=dict(type='str', ),kerberos_timeout_error=dict(type='str', ),kerberos_job_start_error=dict(type='str', ),ntlm_proto_negotiation_success=dict(type='str', ),ntlm_other_error=dict(type='str', ),ntlm_job_start_error=dict(type='str', ),kerberos_response_failure=dict(type='str', ),ntlm_prepare_req_success=dict(type='str', ),ntlm_response_failure=dict(type='str', ),kerberos_polling_control_error=dict(type='str', ),ntlm_prepare_req_failed=dict(type='str', ),kerberos_response_success=dict(type='str', ),kerberos_pw_expiry=dict(type='str', ),ntlm_authentication_success=dict(type='str', ),ntlm_response_timeout=dict(type='str', ),ntlm_authentication_failure=dict(type='str', ),kerberos_request_send=dict(type='str', ),kerberos_pw_change_failure=dict(type='str', ),kerberos_request_normal=dict(type='str', ),ntlm_response_other=dict(type='str', ),kerberos_request_dropped=dict(type='str', ),kerberos_response_other=dict(type='str', ),ntlm_session_setup_success=dict(type='str', ),kerberos_response_error=dict(type='str', ),ntlm_request_normal=dict(type='str', ),ntlm_request_dropped=dict(type='str', ),instance_list=dict(type='list', stats=dict(type='dict', krb_send_req_success=dict(type='str', ),ntlm_auth_success=dict(type='str', ),ntlm_prepare_req_error=dict(type='str', ),ntlm_proto_nego_failure=dict(type='str', ),ntlm_other_error=dict(type='str', ),ntlm_auth_failure=dict(type='str', ),krb_timeout_error=dict(type='str', ),ntlm_session_setup_success=dict(type='str', ),krb_other_error=dict(type='str', ),ntlm_timeout_error=dict(type='str', ),krb_pw_expiry=dict(type='str', ),ntlm_session_setup_failure=dict(type='str', ),krb_pw_change_failure=dict(type='str', ),krb_get_resp_success=dict(type='str', ),ntlm_proto_nego_success=dict(type='str', ),ntlm_prepare_req_success=dict(type='str', ),krb_pw_change_success=dict(type='str', )),name=dict(type='str', required=True, )),kerberos_response_timeout=dict(type='str', ),kerberos_response_get=dict(type='str', ),ntlm_timeout_error=dict(type='str', ),ntlm_proto_negotiation_failure=dict(type='str', ),ntlm_response_success=dict(type='str', )),
        uuid=dict(type='str', ),
        instance_list=dict(type='list', health_check_string=dict(type='str', ),realm=dict(type='str', ),name=dict(type='str', required=True, ),sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','krb_send_req_success','krb_get_resp_success','krb_timeout_error','krb_other_error','krb_pw_expiry','krb_pw_change_success','krb_pw_change_failure','ntlm_proto_nego_success','ntlm_proto_nego_failure','ntlm_session_setup_success','ntlm_session_setup_failure','ntlm_prepare_req_success','ntlm_prepare_req_error','ntlm_auth_success','ntlm_auth_failure','ntlm_timeout_error','ntlm_other_error'])),host=dict(type='dict', hostipv6=dict(type='str', ),hostip=dict(type='str', )),timeout=dict(type='int', ),auth_protocol=dict(type='dict', ntlm_health_check=dict(type='str', ),kport_hm_disable=dict(type='bool', ),ntlm_health_check_disable=dict(type='bool', ),kerberos_port=dict(type='int', ),ntlm_version=dict(type='int', ),kerberos_disable=dict(type='bool', ),ntlm_disable=dict(type='bool', ),kport_hm=dict(type='str', ),kerberos_password_change_port=dict(type='int', )),health_check_disable=dict(type='bool', ),support_apacheds_kdc=dict(type='bool', ),health_check=dict(type='bool', ),uuid=dict(type='str', ))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/server/windows"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/windows"

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
        for k, v in payload["windows"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["windows"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["windows"][k] = v
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
    payload = build_json("windows", module)
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