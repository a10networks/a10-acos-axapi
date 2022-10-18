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
author: A10 Networks
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
    SP_initiated_single_logout_service:
        description:
        - "Field SP_initiated_single_logout_service"
        type: list
        required: False
        suboptions:
            SP_SLO_location:
                description:
                - "The location of SP-initiated single logout service endpoint. (ex. /Logout)"
                type: str
            asynchronous:
                description:
                - "the IDP will not send a logout response to AX"
                type: bool
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
    bad_request_redirect_url:
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
          Logout Success; 'slo-error'= Single Logout Error; 'sp-slo-req'= SP-initiated
          Single Logout Request; 'glo-slo-success'= Total Global Logout Success; 'loc-
          slo-success'= Total Local Logout Success; 'par-slo-success'= Total Partial
          Logout Success; 'other-error'= Other Error;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
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
            sp_slo_req:
                description:
                - "SP-initiated Single Logout Request"
                type: str
            glo_slo_success:
                description:
                - "Total Global Logout Success"
                type: str
            loc_slo_success:
                description:
                - "Total Local Logout Success"
                type: str
            par_slo_success:
                description:
                - "Total Partial Logout Success"
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

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "acs_uri_bypass", "adfs_ws_federation", "artifact_resolution_service", "assertion_consuming_service", "bad_request_redirect_url", "certificate", "entity_id", "metadata_export_service", "name", "packet_capture_template", "require_assertion_signed", "saml_request_signed", "sampling_enable", "service_url", "signature_algorithm",
    "single_logout_service", "soap_tls_certificate_validate", "SP_initiated_single_logout_service", "stats", "user_tag", "uuid",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
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
        'SP_initiated_single_logout_service': {
            'type': 'list',
            'SP_SLO_location': {
                'type': 'str',
                },
            'asynchronous': {
                'type': 'bool',
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
        'bad_request_redirect_url': {
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
                'type': 'str',
                'choices': ['all', 'sp-metadata-export-req', 'sp-metadata-export-success', 'login-auth-req', 'login-auth-resp', 'acs-req', 'acs-success', 'acs-authz-fail', 'acs-error', 'slo-req', 'slo-success', 'slo-error', 'sp-slo-req', 'glo-slo-success', 'loc-slo-success', 'par-slo-success', 'other-error']
                }
            },
        'packet_capture_template': {
            'type': 'str',
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
            'sp_slo_req': {
                'type': 'str',
                },
            'glo_slo_success': {
                'type': 'str',
                },
            'loc_slo_success': {
                'type': 'str',
                },
            'par_slo_success': {
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
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/saml/service-provider/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["service-provider"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["service-provider"].get(k) != v:
            change_results["changed"] = True
            config_changes["service-provider"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("service-provider", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["service-provider"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["service-provider-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["service-provider"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
