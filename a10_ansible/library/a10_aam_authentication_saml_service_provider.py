#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_saml_service_provider
description:
    - None
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
    name:
        description:
        - "None"
        required: True
    certificate:
        description:
        - "None"
        required: False
    require_assertion_signed:
        description:
        - "Field require_assertion_signed"
        required: False
        suboptions:
            require_assertion_signed_enable:
                description:
                - "None"
    artifact_resolution_service:
        description:
        - "Field artifact_resolution_service"
        required: False
        suboptions:
            artifact_location:
                description:
                - "None"
            artifact_binding:
                description:
                - "None"
            artifact_index:
                description:
                - "None"
    service_url:
        description:
        - "None"
        required: False
    entity_id:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    assertion_consuming_service:
        description:
        - "Field assertion_consuming_service"
        required: False
        suboptions:
            assertion_index:
                description:
                - "None"
            assertion_binding:
                description:
                - "None"
            assertion_location:
                description:
                - "None"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    saml_request_signed:
        description:
        - "Field saml_request_signed"
        required: False
        suboptions:
            saml_request_signed_disable:
                description:
                - "None"
    metadata_export_service:
        description:
        - "Field metadata_export_service"
        required: False
        suboptions:
            md_export_location:
                description:
                - "None"
            sign_xml:
                description:
                - "None"
    adfs_ws_federation:
        description:
        - "Field adfs_ws_federation"
        required: False
        suboptions:
            ws_federation_enable:
                description:
                - "None"
    soap_tls_certificate_validate:
        description:
        - "Field soap_tls_certificate_validate"
        required: False
        suboptions:
            soap_tls_certificate_validate_disable:
                description:
                - "None"
    single_logout_service:
        description:
        - "Field single_logout_service"
        required: False
        suboptions:
            SLO_binding:
                description:
                - "None"
            SLO_location:
                description:
                - "None"
    signature_algorithm:
        description:
        - "None"
        required: False
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
AVAILABLE_PROPERTIES = ["adfs_ws_federation","artifact_resolution_service","assertion_consuming_service","certificate","entity_id","metadata_export_service","name","require_assertion_signed","saml_request_signed","sampling_enable","service_url","signature_algorithm","single_logout_service","soap_tls_certificate_validate","user_tag","uuid",]

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
        name=dict(type='str',required=True,),
        certificate=dict(type='str',),
        require_assertion_signed=dict(type='dict',require_assertion_signed_enable=dict(type='bool',)),
        artifact_resolution_service=dict(type='list',artifact_location=dict(type='str',),artifact_binding=dict(type='str',choices=['soap']),artifact_index=dict(type='int',)),
        service_url=dict(type='str',),
        entity_id=dict(type='str',),
        user_tag=dict(type='str',),
        assertion_consuming_service=dict(type='list',assertion_index=dict(type='int',),assertion_binding=dict(type='str',choices=['artifact','paos','post']),assertion_location=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sp-metadata-export-req','sp-metadata-export-success','login-auth-req','login-auth-resp','acs-req','acs-success','acs-authz-fail','acs-error','slo-req','slo-success','slo-error','other-error'])),
        saml_request_signed=dict(type='dict',saml_request_signed_disable=dict(type='bool',)),
        metadata_export_service=dict(type='dict',md_export_location=dict(type='str',),sign_xml=dict(type='bool',)),
        adfs_ws_federation=dict(type='dict',ws_federation_enable=dict(type='bool',)),
        soap_tls_certificate_validate=dict(type='dict',soap_tls_certificate_validate_disable=dict(type='bool',)),
        single_logout_service=dict(type='list',SLO_binding=dict(type='str',choices=['post','redirect','soap']),SLO_location=dict(type='str',)),
        signature_algorithm=dict(type='str',choices=['SHA1','SHA256']),
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
    payload = build_json("service-provider", module)
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
    payload = build_json("service-provider", module)
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