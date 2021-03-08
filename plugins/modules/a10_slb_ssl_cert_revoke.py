#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_ssl_cert_revoke
description:
    - Configure ssl-cert-revoke-stats
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
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'ocsp_stapling_response_good'= OCSP stapling response good;
          'ocsp_chain_status_good'= Certificate chain status good;
          'ocsp_chain_status_revoked'= Certificate chain status revoked;
          'ocsp_chain_status_unknown'= Certificate chain status unknown; 'ocsp_request'=
          OCSP requests; 'ocsp_response'= OCSP responses; 'ocsp_connection_error'= OCSP
          connection error; 'ocsp_uri_not_found'= OCSP URI not found; 'ocsp_uri_https'=
          Log OCSP URI https; 'ocsp_uri_unsupported'= OCSP URI unsupported;
          'ocsp_response_status_good'= OCSP response status good;
          'ocsp_response_status_revoked'= OCSP response status revoked;
          'ocsp_response_status_unknown'= OCSP response status unknown;
          'ocsp_cache_status_good'= OCSP cache status good; 'ocsp_cache_status_revoked'=
          OCSP cache status revoked; 'ocsp_cache_miss'= OCSP cache miss;
          'ocsp_cache_expired'= OCSP cache expired; 'ocsp_other_error'= Log OCSP other
          errors; 'ocsp_response_no_nonce'= Log OCSP other errors;
          'ocsp_response_nonce_error'= Log OCSP other errors; 'crl_request'= CRL
          requests; 'crl_response'= CRL responses; 'crl_connection_error'= CRL connection
          errors; 'crl_uri_not_found'= CRL URI not found; 'crl_uri_https'= CRL URI https;
          'crl_uri_unsupported'= CRL URI unsupported; 'crl_response_status_good'= CRL
          response status good; 'crl_response_status_revoked'= CRL response status
          revoked; 'crl_response_status_unknown'= CRL response status unknown;
          'crl_cache_status_good'= CRL cache status good; 'crl_cache_status_revoked'= CRL
          cache status revoked; 'crl_other_error'= CRL other errors;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ocsp_stapling_response_good:
                description:
                - "OCSP stapling response good"
                type: str
            ocsp_chain_status_good:
                description:
                - "Certificate chain status good"
                type: str
            ocsp_chain_status_revoked:
                description:
                - "Certificate chain status revoked"
                type: str
            ocsp_chain_status_unknown:
                description:
                - "Certificate chain status unknown"
                type: str
            ocsp_request:
                description:
                - "OCSP requests"
                type: str
            ocsp_response:
                description:
                - "OCSP responses"
                type: str
            ocsp_connection_error:
                description:
                - "OCSP connection error"
                type: str
            ocsp_uri_not_found:
                description:
                - "OCSP URI not found"
                type: str
            ocsp_uri_https:
                description:
                - "Log OCSP URI https"
                type: str
            ocsp_uri_unsupported:
                description:
                - "OCSP URI unsupported"
                type: str
            ocsp_response_status_good:
                description:
                - "OCSP response status good"
                type: str
            ocsp_response_status_revoked:
                description:
                - "OCSP response status revoked"
                type: str
            ocsp_response_status_unknown:
                description:
                - "OCSP response status unknown"
                type: str
            ocsp_cache_status_good:
                description:
                - "OCSP cache status good"
                type: str
            ocsp_cache_status_revoked:
                description:
                - "OCSP cache status revoked"
                type: str
            ocsp_cache_miss:
                description:
                - "OCSP cache miss"
                type: str
            ocsp_cache_expired:
                description:
                - "OCSP cache expired"
                type: str
            ocsp_other_error:
                description:
                - "Log OCSP other errors"
                type: str
            ocsp_response_no_nonce:
                description:
                - "Log OCSP other errors"
                type: str
            ocsp_response_nonce_error:
                description:
                - "Log OCSP other errors"
                type: str
            crl_request:
                description:
                - "CRL requests"
                type: str
            crl_response:
                description:
                - "CRL responses"
                type: str
            crl_connection_error:
                description:
                - "CRL connection errors"
                type: str
            crl_uri_not_found:
                description:
                - "CRL URI not found"
                type: str
            crl_uri_https:
                description:
                - "CRL URI https"
                type: str
            crl_uri_unsupported:
                description:
                - "CRL URI unsupported"
                type: str
            crl_response_status_good:
                description:
                - "CRL response status good"
                type: str
            crl_response_status_revoked:
                description:
                - "CRL response status revoked"
                type: str
            crl_response_status_unknown:
                description:
                - "CRL response status unknown"
                type: str
            crl_cache_status_good:
                description:
                - "CRL cache status good"
                type: str
            crl_cache_status_revoked:
                description:
                - "CRL cache status revoked"
                type: str
            crl_other_error:
                description:
                - "CRL other errors"
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
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'ocsp_stapling_response_good',
                    'ocsp_chain_status_good', 'ocsp_chain_status_revoked',
                    'ocsp_chain_status_unknown', 'ocsp_request',
                    'ocsp_response', 'ocsp_connection_error',
                    'ocsp_uri_not_found', 'ocsp_uri_https',
                    'ocsp_uri_unsupported', 'ocsp_response_status_good',
                    'ocsp_response_status_revoked',
                    'ocsp_response_status_unknown', 'ocsp_cache_status_good',
                    'ocsp_cache_status_revoked', 'ocsp_cache_miss',
                    'ocsp_cache_expired', 'ocsp_other_error',
                    'ocsp_response_no_nonce', 'ocsp_response_nonce_error',
                    'crl_request', 'crl_response', 'crl_connection_error',
                    'crl_uri_not_found', 'crl_uri_https',
                    'crl_uri_unsupported', 'crl_response_status_good',
                    'crl_response_status_revoked',
                    'crl_response_status_unknown', 'crl_cache_status_good',
                    'crl_cache_status_revoked', 'crl_other_error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'ocsp_stapling_response_good': {
                'type': 'str',
            },
            'ocsp_chain_status_good': {
                'type': 'str',
            },
            'ocsp_chain_status_revoked': {
                'type': 'str',
            },
            'ocsp_chain_status_unknown': {
                'type': 'str',
            },
            'ocsp_request': {
                'type': 'str',
            },
            'ocsp_response': {
                'type': 'str',
            },
            'ocsp_connection_error': {
                'type': 'str',
            },
            'ocsp_uri_not_found': {
                'type': 'str',
            },
            'ocsp_uri_https': {
                'type': 'str',
            },
            'ocsp_uri_unsupported': {
                'type': 'str',
            },
            'ocsp_response_status_good': {
                'type': 'str',
            },
            'ocsp_response_status_revoked': {
                'type': 'str',
            },
            'ocsp_response_status_unknown': {
                'type': 'str',
            },
            'ocsp_cache_status_good': {
                'type': 'str',
            },
            'ocsp_cache_status_revoked': {
                'type': 'str',
            },
            'ocsp_cache_miss': {
                'type': 'str',
            },
            'ocsp_cache_expired': {
                'type': 'str',
            },
            'ocsp_other_error': {
                'type': 'str',
            },
            'ocsp_response_no_nonce': {
                'type': 'str',
            },
            'ocsp_response_nonce_error': {
                'type': 'str',
            },
            'crl_request': {
                'type': 'str',
            },
            'crl_response': {
                'type': 'str',
            },
            'crl_connection_error': {
                'type': 'str',
            },
            'crl_uri_not_found': {
                'type': 'str',
            },
            'crl_uri_https': {
                'type': 'str',
            },
            'crl_uri_unsupported': {
                'type': 'str',
            },
            'crl_response_status_good': {
                'type': 'str',
            },
            'crl_response_status_revoked': {
                'type': 'str',
            },
            'crl_response_status_unknown': {
                'type': 'str',
            },
            'crl_cache_status_good': {
                'type': 'str',
            },
            'crl_cache_status_revoked': {
                'type': 'str',
            },
            'crl_other_error': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

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
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

    f_dict = {}

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
        for k, v in payload["ssl-cert-revoke"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ssl-cert-revoke"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ssl-cert-revoke"][k] = v
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
    payload = build_json("ssl-cert-revoke", module)
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
