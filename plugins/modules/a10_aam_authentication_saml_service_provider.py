#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_saml_service_provider
description:
    - Authentication service provider
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "Specify SAML authentication service provider name"
        type: str
        required: True
    adfs_ws_federation:
        description:
        - "Field adfs_ws_federation"
        type: dict
        required: False
        suboptions:
            ws_federation_enable:
                description:
                - "Enable ADFS WS-Federation"
                type: bool
    artifact_resolution_service:
        description:
        - "Field artifact_resolution_service"
        type: list
        required: False
        suboptions:
            artifact_index:
                description:
                - "The index of artifact resolution service"
                type: int
            artifact_location:
                description:
                - "The location of artifact resolution service. (ex. /SAML/POST)"
                type: str
            artifact_binding:
                description:
                - "'soap'= SOAP binding of artifact resolution service;"
                type: str
    assertion_consuming_service:
        description:
        - "Field assertion_consuming_service"
        type: list
        required: False
        suboptions:
            assertion_index:
                description:
                - "The index of assertion consuming service"
                type: int
            assertion_location:
                description:
                - "The location of assertion consuming service endpoint. (ex. /SAML/POST)"
                type: str
            assertion_binding:
                description:
                - "'artifact'= Artifact binding of assertion consuming service; 'paos'= PAOS
          binding of assertion consuming service; 'post'= POST binding of assertion
          consuming service;"
                type: str
    single_logout_service:
        description:
        - "Field single_logout_service"
        type: list
        required: False
        suboptions:
            SLO_location:
                description:
                - "The location of name-id management service. (ex. /SAML/POST)"
                type: str
            SLO_binding:
                description:
                - "'post'= POST binding of single logout service; 'redirect'= Redirect binding of
          single logout service; 'soap'= SOAP binding of single logout service;"
                type: str
    metadata_export_service:
        description:
        - "Field metadata_export_service"
        type: dict
        required: False
        suboptions:
            md_export_location:
                description:
                - "Specify the URI to export SP metadata (Export URI. Default is /A10SP_Metadata)"
                type: str
            sign_xml:
                description:
                - "Sign exported SP metadata XML with SP's certificate"
                type: bool
    certificate:
        description:
        - "SAML service provider certificate file (PFX format is required.)"
        type: str
        required: False
    entity_id:
        description:
        - "SAML service provider entity ID"
        type: str
        required: False
    saml_request_signed:
        description:
        - "Field saml_request_signed"
        type: dict
        required: False
        suboptions:
            saml_request_signed_disable:
                description:
                - "Disable signing signature for SAML (Authn/Artifact Resolve) requests"
                type: bool
    soap_tls_certificate_validate:
        description:
        - "Field soap_tls_certificate_validate"
        type: dict
        required: False
        suboptions:
            soap_tls_certificate_validate_disable:
                description:
                - "Disable verification for server certificate in TLS session when resolving
          artificate"
                type: bool
    signature_algorithm:
        description:
        - "'SHA1'= use SHA1 as signature algorithm (default); 'SHA256'= use SHA256 as
          signature algorithm;"
        type: str
        required: False
    require_assertion_signed:
        description:
        - "Field require_assertion_signed"
        type: dict
        required: False
        suboptions:
            require_assertion_signed_enable:
                description:
                - "Enable required signing of SAML assertion"
                type: bool
    service_url:
        description:
        - "SAML service provider service URL (ex. https=//www.a10networks.com/saml.sso)"
        type: str
        required: False
    bad_request_redirect_uri:
        description:
        - "Specify URL to redirect"
        type: str
        required: False
    acs_uri_bypass:
        description:
        - "After user authenticated, bypass requests with assertion-consuming-service
          location URI"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'sp-metadata-export-req'= Metadata Export Request; 'sp-metadata-
          export-success'= Metadata Export Success; 'login-auth-req'= Login
          Authentication Request; 'login-auth-resp'= Login Authentication Response; 'acs-
          req'= SAML Single-Sign-On Request; 'acs-success'= SAML Single-Sign-On Success;
          'acs-authz-fail'= SAML Single-Sign-On Authorization Fail; 'acs-error'= SAML
          Single-Sign-On Error; 'slo-req'= Single Logout Request; 'slo-success'= Single
          Logout Success; 'slo-error'= Single Logout Error; 'other-error'= Other Error;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            sp_metadata_export_req:
                description:
                - "Metadata Export Request"
                type: str
            sp_metadata_export_success:
                description:
                - "Metadata Export Success"
                type: str
            login_auth_req:
                description:
                - "Login Authentication Request"
                type: str
            login_auth_resp:
                description:
                - "Login Authentication Response"
                type: str
            acs_req:
                description:
                - "SAML Single-Sign-On Request"
                type: str
            acs_success:
                description:
                - "SAML Single-Sign-On Success"
                type: str
            acs_authz_fail:
                description:
                - "SAML Single-Sign-On Authorization Fail"
                type: str
            acs_error:
                description:
                - "SAML Single-Sign-On Error"
                type: str
            slo_req:
                description:
                - "Single Logout Request"
                type: str
            slo_success:
                description:
                - "Single Logout Success"
                type: str
            slo_error:
                description:
                - "Single Logout Error"
                type: str
            other_error:
                description:
                - "Other Error"
                type: str
            name:
                description:
                - "Specify SAML authentication service provider name"
                type: str

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "acs_uri_bypass",
    "adfs_ws_federation",
    "artifact_resolution_service",
    "assertion_consuming_service",
    "bad_request_redirect_uri",
    "certificate",
    "entity_id",
    "metadata_export_service",
    "name",
    "require_assertion_signed",
    "saml_request_signed",
    "sampling_enable",
    "service_url",
    "signature_algorithm",
    "single_logout_service",
    "soap_tls_certificate_validate",
    "stats",
    "user_tag",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
        },
        'adfs_ws_federation': {
            'type': 'dict',
            'ws_federation_enable': {
                'type': 'bool',
            }
        },
        'artifact_resolution_service': {
            'type': 'list',
            'artifact_index': {
                'type': 'int',
            },
            'artifact_location': {
                'type': 'str',
            },
            'artifact_binding': {
                'type': 'str',
                'choices': ['soap']
            }
        },
        'assertion_consuming_service': {
            'type': 'list',
            'assertion_index': {
                'type': 'int',
            },
            'assertion_location': {
                'type': 'str',
            },
            'assertion_binding': {
                'type': 'str',
                'choices': ['artifact', 'paos', 'post']
            }
        },
        'single_logout_service': {
            'type': 'list',
            'SLO_location': {
                'type': 'str',
            },
            'SLO_binding': {
                'type': 'str',
                'choices': ['post', 'redirect', 'soap']
            }
        },
        'metadata_export_service': {
            'type': 'dict',
            'md_export_location': {
                'type': 'str',
            },
            'sign_xml': {
                'type': 'bool',
            }
        },
        'certificate': {
            'type': 'str',
        },
        'entity_id': {
            'type': 'str',
        },
        'saml_request_signed': {
            'type': 'dict',
            'saml_request_signed_disable': {
                'type': 'bool',
            }
        },
        'soap_tls_certificate_validate': {
            'type': 'dict',
            'soap_tls_certificate_validate_disable': {
                'type': 'bool',
            }
        },
        'signature_algorithm': {
            'type': 'str',
            'choices': ['SHA1', 'SHA256']
        },
        'require_assertion_signed': {
            'type': 'dict',
            'require_assertion_signed_enable': {
                'type': 'bool',
            }
        },
        'service_url': {
            'type': 'str',
        },
        'bad_request_redirect_uri': {
            'type': 'str',
        },
        'acs_uri_bypass': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'sp-metadata-export-req',
                    'sp-metadata-export-success', 'login-auth-req',
                    'login-auth-resp', 'acs-req', 'acs-success',
                    'acs-authz-fail', 'acs-error', 'slo-req', 'slo-success',
                    'slo-error', 'other-error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'sp_metadata_export_req': {
                'type': 'str',
            },
            'sp_metadata_export_success': {
                'type': 'str',
            },
            'login_auth_req': {
                'type': 'str',
            },
            'login_auth_resp': {
                'type': 'str',
            },
            'acs_req': {
                'type': 'str',
            },
            'acs_success': {
                'type': 'str',
            },
            'acs_authz_fail': {
                'type': 'str',
            },
            'acs_error': {
                'type': 'str',
            },
            'slo_req': {
                'type': 'str',
            },
            'slo_success': {
                'type': 'str',
            },
            'slo_error': {
                'type': 'str',
            },
            'other_error': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
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
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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

    for k, v in param.items():
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
    return {title: data}


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
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
                    if result["changed"] is not True:
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

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
