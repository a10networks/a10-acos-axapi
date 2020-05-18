#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_saml_service_provider
description:
    - Authentication service provider
short_description: Configures A10 aam.authentication.saml.service-provider
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            login_auth_req:
                description:
                - "Login Authentication Request"
            slo_error:
                description:
                - "Single Logout Error"
            name:
                description:
                - "Specify SAML authentication service provider name"
            sp_metadata_export_success:
                description:
                - "Metadata Export Success"
            acs_authz_fail:
                description:
                - "SAML Single-Sign-On Authorization Fail"
            slo_req:
                description:
                - "Single Logout Request"
            login_auth_resp:
                description:
                - "Login Authentication Response"
            slo_success:
                description:
                - "Single Logout Success"
            acs_success:
                description:
                - "SAML Single-Sign-On Success"
            acs_error:
                description:
                - "SAML Single-Sign-On Error"
            other_error:
                description:
                - "Other Error"
            acs_req:
                description:
                - "SAML Single-Sign-On Request"
            sp_metadata_export_req:
                description:
                - "Metadata Export Request"
    name:
        description:
        - "Specify SAML authentication service provider name"
        required: True
    certificate:
        description:
        - "SAML service provider certificate file (PFX format is required.)"
        required: False
    require_assertion_signed:
        description:
        - "Field require_assertion_signed"
        required: False
        suboptions:
            require_assertion_signed_enable:
                description:
                - "Enable required signing of SAML assertion"
    artifact_resolution_service:
        description:
        - "Field artifact_resolution_service"
        required: False
        suboptions:
            artifact_location:
                description:
                - "The location of artifact resolution service. (ex. /SAML/POST)"
            artifact_binding:
                description:
                - "'soap'= SOAP binding of artifact resolution service; "
            artifact_index:
                description:
                - "The index of artifact resolution service"
    service_url:
        description:
        - "SAML service provider service URL (ex. https=//www.a10networks.com/saml.sso)"
        required: False
    entity_id:
        description:
        - "SAML service provider entity ID"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    signature_algorithm:
        description:
        - "'SHA1'= use SHA1 as signature algorithm (default); 'SHA256'= use SHA256 as signature algorithm; "
        required: False
    assertion_consuming_service:
        description:
        - "Field assertion_consuming_service"
        required: False
        suboptions:
            assertion_index:
                description:
                - "The index of assertion consuming service"
            assertion_binding:
                description:
                - "'artifact'= Artifact binding of assertion consuming service; 'paos'= PAOS binding of assertion consuming service; 'post'= POST binding of assertion consuming service; "
            assertion_location:
                description:
                - "The location of assertion consuming service endpoint. (ex. /SAML/POST)"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'sp-metadata-export-req'= Metadata Export Request; 'sp-metadata-export-success'= Metadata Export Success; 'login-auth-req'= Login Authentication Request; 'login-auth-resp'= Login Authentication Response; 'acs-req'= SAML Single-Sign-On Request; 'acs-success'= SAML Single-Sign-On Success; 'acs-authz-fail'= SAML Single-Sign-On Authorization Fail; 'acs-error'= SAML Single-Sign-On Error; 'slo-req'= Single Logout Request; 'slo-success'= Single Logout Success; 'slo-error'= Single Logout Error; 'other-error'= Other Error; "
    saml_request_signed:
        description:
        - "Field saml_request_signed"
        required: False
        suboptions:
            saml_request_signed_disable:
                description:
                - "Disable signing signature for SAML (Authn/Artifact Resolve) requests"
    metadata_export_service:
        description:
        - "Field metadata_export_service"
        required: False
        suboptions:
            md_export_location:
                description:
                - "Specify the URI to export SP metadata (Export URI. Default is /A10SP_Metadata)"
            sign_xml:
                description:
                - "Sign exported SP metadata XML with SP's certificate"
    adfs_ws_federation:
        description:
        - "Field adfs_ws_federation"
        required: False
        suboptions:
            ws_federation_enable:
                description:
                - "Enable ADFS WS-Federation"
    soap_tls_certificate_validate:
        description:
        - "Field soap_tls_certificate_validate"
        required: False
        suboptions:
            soap_tls_certificate_validate_disable:
                description:
                - "Disable verification for server certificate in TLS session when resolving artificate"
    single_logout_service:
        description:
        - "Field single_logout_service"
        required: False
        suboptions:
            SLO_binding:
                description:
                - "'post'= POST binding of single logout service; 'redirect'= Redirect binding of single logout service; 'soap'= SOAP binding of single logout service; "
            SLO_location:
                description:
                - "The location of name-id management service. (ex. /SAML/POST)"
    acs_uri_bypass:
        description:
        - "After user authenticated, bypass requests with assertion-consuming-service location URI"
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
AVAILABLE_PROPERTIES = ["acs_uri_bypass","adfs_ws_federation","artifact_resolution_service","assertion_consuming_service","certificate","entity_id","metadata_export_service","name","require_assertion_signed","saml_request_signed","sampling_enable","service_url","signature_algorithm","single_logout_service","soap_tls_certificate_validate","stats","user_tag","uuid",]

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
        stats=dict(type='dict', login_auth_req=dict(type='str', ), slo_error=dict(type='str', ), name=dict(type='str', required=True, ), sp_metadata_export_success=dict(type='str', ), acs_authz_fail=dict(type='str', ), slo_req=dict(type='str', ), login_auth_resp=dict(type='str', ), slo_success=dict(type='str', ), acs_success=dict(type='str', ), acs_error=dict(type='str', ), other_error=dict(type='str', ), acs_req=dict(type='str', ), sp_metadata_export_req=dict(type='str', )),
        name=dict(type='str', required=True, ),
        certificate=dict(type='str', ),
        require_assertion_signed=dict(type='dict', require_assertion_signed_enable=dict(type='bool', )),
        artifact_resolution_service=dict(type='list', artifact_location=dict(type='str', ), artifact_binding=dict(type='str', choices=['soap']), artifact_index=dict(type='int', )),
        service_url=dict(type='str', ),
        entity_id=dict(type='str', ),
        user_tag=dict(type='str', ),
        signature_algorithm=dict(type='str', choices=['SHA1', 'SHA256']),
        assertion_consuming_service=dict(type='list', assertion_index=dict(type='int', ), assertion_binding=dict(type='str', choices=['artifact', 'paos', 'post']), assertion_location=dict(type='str', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'sp-metadata-export-req', 'sp-metadata-export-success', 'login-auth-req', 'login-auth-resp', 'acs-req', 'acs-success', 'acs-authz-fail', 'acs-error', 'slo-req', 'slo-success', 'slo-error', 'other-error'])),
        saml_request_signed=dict(type='dict', saml_request_signed_disable=dict(type='bool', )),
        metadata_export_service=dict(type='dict', md_export_location=dict(type='str', ), sign_xml=dict(type='bool', )),
        adfs_ws_federation=dict(type='dict', ws_federation_enable=dict(type='bool', )),
        soap_tls_certificate_validate=dict(type='dict', soap_tls_certificate_validate_disable=dict(type='bool', )),
        single_logout_service=dict(type='list', SLO_binding=dict(type='str', choices=['post', 'redirect', 'soap']), SLO_location=dict(type='str', )),
        acs_uri_bypass=dict(type='bool', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/saml/service-provider/{name}"

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
    url_base = "/axapi/v3/aam/authentication/saml/service-provider/{name}"

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
        for k, v in payload["service-provider"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["service-provider"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["service-provider"][k] = v
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
    payload = build_json("service-provider", module)
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