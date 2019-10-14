#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["acs_uri_bypass","adfs_ws_federation","artifact_resolution_service","assertion_consuming_service","certificate","entity_id","metadata_export_service","name","require_assertion_signed","saml_request_signed","sampling_enable","service_url","signature_algorithm","single_logout_service","soap_tls_certificate_validate","user_tag","uuid",]

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
        name=dict(type='str',required=True,),
        certificate=dict(type='str',),
        require_assertion_signed=dict(type='dict',require_assertion_signed_enable=dict(type='bool',)),
        artifact_resolution_service=dict(type='list',artifact_location=dict(type='str',),artifact_binding=dict(type='str',choices=['soap']),artifact_index=dict(type='int',)),
        service_url=dict(type='str',),
        entity_id=dict(type='str',),
        user_tag=dict(type='str',),
        signature_algorithm=dict(type='str',choices=['SHA1','SHA256']),
        assertion_consuming_service=dict(type='list',assertion_index=dict(type='int',),assertion_binding=dict(type='str',choices=['artifact','paos','post']),assertion_location=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sp-metadata-export-req','sp-metadata-export-success','login-auth-req','login-auth-resp','acs-req','acs-success','acs-authz-fail','acs-error','slo-req','slo-success','slo-error','other-error'])),
        saml_request_signed=dict(type='dict',saml_request_signed_disable=dict(type='bool',)),
        metadata_export_service=dict(type='dict',md_export_location=dict(type='str',),sign_xml=dict(type='bool',)),
        adfs_ws_federation=dict(type='dict',ws_federation_enable=dict(type='bool',)),
        soap_tls_certificate_validate=dict(type='dict',soap_tls_certificate_validate_disable=dict(type='bool',)),
        single_logout_service=dict(type='list',SLO_binding=dict(type='str',choices=['post','redirect','soap']),SLO_location=dict(type='str',)),
        acs_uri_bypass=dict(type='bool',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/saml/service-provider/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/saml/service-provider/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["service-provider"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
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
    payload = build_json("service-provider", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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