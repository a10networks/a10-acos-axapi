#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_server
description:
    - Authentication server configuration
short_description: Configures A10 aam.authentication.server
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
    windows:
        description:
        - "Field windows"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            instance_list:
                description:
                - "Field instance_list"
    ldap:
        description:
        - "Field ldap"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            instance_list:
                description:
                - "Field instance_list"
    radius:
        description:
        - "Field radius"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            instance_list:
                description:
                - "Field instance_list"
    uuid:
        description:
        - "uuid of the object"
        required: False
    ocsp:
        description:
        - "Field ocsp"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            instance_list:
                description:
                - "Field instance_list"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["ldap","ocsp","radius","uuid","windows",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        windows=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','kerberos-request-send','kerberos-response-get','kerberos-timeout-error','kerberos-other-error','ntlm-authentication-success','ntlm-authentication-failure','ntlm-proto-negotiation-success','ntlm-proto-negotiation-failure','ntlm-session-setup-success','ntlm-session-setup-failed','kerberos-request-normal','kerberos-request-dropped','kerberos-response-success','kerberos-response-failure','kerberos-response-error','kerberos-response-timeout','kerberos-response-other','kerberos-job-start-error','kerberos-polling-control-error','ntlm-prepare-req-success','ntlm-prepare-req-failed','ntlm-timeout-error','ntlm-other-error','ntlm-request-normal','ntlm-request-dropped','ntlm-response-success','ntlm-response-failure','ntlm-response-error','ntlm-response-timeout','ntlm-response-other','ntlm-job-start-error','ntlm-polling-control-error','kerberos-pw-expiry','kerberos-pw-change-success','kerberos-pw-change-failure'])),uuid=dict(type='str',),instance_list=dict(type='list',health_check_string=dict(type='str',),realm=dict(type='str',),name=dict(type='str',required=True,),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','krb_send_req_success','krb_get_resp_success','krb_timeout_error','krb_other_error','krb_pw_expiry','krb_pw_change_success','krb_pw_change_failure','ntlm_proto_nego_success','ntlm_proto_nego_failure','ntlm_session_setup_success','ntlm_session_setup_failure','ntlm_prepare_req_success','ntlm_prepare_req_error','ntlm_auth_success','ntlm_auth_failure','ntlm_timeout_error','ntlm_other_error'])),host=dict(type='dict',hostipv6=dict(type='str',),hostip=dict(type='str',)),timeout=dict(type='int',),auth_protocol=dict(type='dict',ntlm_health_check=dict(type='str',),kport_hm_disable=dict(type='bool',),ntlm_health_check_disable=dict(type='bool',),kerberos_port=dict(type='int',),ntlm_version=dict(type='int',),kerberos_disable=dict(type='bool',),ntlm_disable=dict(type='bool',),kport_hm=dict(type='str',),kerberos_password_change_port=dict(type='int',)),health_check_disable=dict(type='bool',),support_apacheds_kdc=dict(type='bool',),health_check=dict(type='bool',),uuid=dict(type='str',))),
        ldap=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','admin-bind-success','admin-bind-failure','bind-success','bind-failure','search-success','search-failure','authorize-success','authorize-failure','timeout-error','other-error','request','request-normal','request-dropped','response-success','response-failure','response-error','response-timeout','response-other','job-start-error','polling-control-error','ssl-session-created','ssl-session-failure','ldaps-idle-conn-num','ldaps-inuse-conn-num','pw-expiry','pw-change-success','pw-change-failure'])),uuid=dict(type='str',),instance_list=dict(type='list',health_check_disable=dict(type='bool',),protocol=dict(type='str',choices=['ldap','ldaps','starttls']),encrypted=dict(type='str',),port=dict(type='int',),ldaps_conn_reuse_idle_timeout=dict(type='int',),port_hm=dict(type='str',),uuid=dict(type='str',),admin_dn=dict(type='str',),default_domain=dict(type='str',),auth_type=dict(type='str',choices=['ad','open-ldap']),admin_secret=dict(type='bool',),pwdmaxage=dict(type='int',),health_check_string=dict(type='str',),derive_bind_dn=dict(type='dict',username_attr=dict(type='str',)),prompt_pw_change_before_exp=dict(type='int',),base=dict(type='str',),secret_string=dict(type='str',),name=dict(type='str',required=True,),port_hm_disable=dict(type='bool',),host=dict(type='dict',hostipv6=dict(type='str',),hostip=dict(type='str',)),ca_cert=dict(type='str',),bind_with_dn=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','admin-bind-success','admin-bind-failure','bind-success','bind-failure','search-success','search-failure','authorize-success','authorize-failure','timeout-error','other-error','request','ssl-session-created','ssl-session-failure','pw_expiry','pw_change_success','pw_change_failure'])),dn_attribute=dict(type='str',),timeout=dict(type='int',),health_check=dict(type='bool',))),
        radius=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','authen_success','authen_failure','authorize_success','authorize_failure','access_challenge','timeout_error','other_error','request','request-normal','request-dropped','response-success','response-failure','response-error','response-timeout','response-other','job-start-error','polling-control-error','accounting-request-sent','accounting-success','accounting-failure'])),uuid=dict(type='str',),instance_list=dict(type='list',auth_type=dict(type='str',choices=['pap','mschapv2','mschapv2-pap']),health_check_string=dict(type='str',),retry=dict(type='int',),port_hm=dict(type='str',),name=dict(type='str',required=True,),port_hm_disable=dict(type='bool',),encrypted=dict(type='str',),interval=dict(type='int',),accounting_port=dict(type='int',),port=dict(type='int',),health_check=dict(type='bool',),acct_port_hm_disable=dict(type='bool',),secret=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','authen_success','authen_failure','authorize_success','authorize_failure','access_challenge','timeout_error','other_error','request','accounting-request-sent','accounting-success','accounting-failure'])),host=dict(type='dict',hostipv6=dict(type='str',),hostip=dict(type='str',)),health_check_disable=dict(type='bool',),secret_string=dict(type='str',),acct_port_hm=dict(type='str',),uuid=dict(type='str',))),
        uuid=dict(type='str',),
        ocsp=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','stapling-certificate-good','stapling-certificate-revoked','stapling-certificate-unknown','stapling-request-normal','stapling-request-dropped','stapling-response-success','stapling-response-failure','stapling-response-error','stapling-response-timeout','stapling-response-other','request-normal','request-dropped','response-success','response-failure','response-error','response-timeout','response-other','job-start-error','polling-control-error'])),uuid=dict(type='str',),instance_list=dict(type='list',health_check_string=dict(type='str',),responder_ca=dict(type='str',),name=dict(type='str',required=True,),url=dict(type='str',),responder_cert=dict(type='str',),health_check_disable=dict(type='bool',),http_version=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','request','certificate-good','certificate-revoked','certificate-unknown','timeout','fail','stapling-request','stapling-certificate-good','stapling-certificate-revoked','stapling-certificate-unknown','stapling-timeout','stapling-fail'])),version_type=dict(type='str',choices=['1.1']),port_health_check_disable=dict(type='bool',),port_health_check=dict(type='str',),health_check=dict(type='bool',),uuid=dict(type='str',)))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/server"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server"

    f_dict = {}

    return url_base.format(**f_dict)

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

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["server"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["server"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["server"][k] = v
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
    payload = build_json("server", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("server", module)
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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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