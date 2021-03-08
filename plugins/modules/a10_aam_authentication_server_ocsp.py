#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_server_ocsp
description:
    - OCSP Authentication Server
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
                - "'all'= all; 'stapling-certificate-good'= Total OCSP Stapling Good Certificate
          Response; 'stapling-certificate-revoked'= Total OCSP Stapling Revoked
          Certificate Response; 'stapling-certificate-unknown'= Total OCSP Stapling
          Unknown Certificate Response; 'stapling-request-normal'= Total OSCP Stapling
          Normal Request; 'stapling-request-dropped'= Total OCSP Stapling Dropped
          Request; 'stapling-response-success'= Total OCSP Stapling Success Response;
          'stapling-response-failure'= Total OCSP Stapling Failure Response; 'stapling-
          response-error'= Total OCSP Stapling Error Response; 'stapling-response-
          timeout'= Total OCSP Stapling Timeout Response; 'stapling-response-other'=
          Total OCSP Stapling Other Response; 'request-normal'= Total OSCP Normal
          Request; 'request-dropped'= Total OCSP Dropped Request; 'response-success'=
          Total OCSP Success Response; 'response-failure'= Total OCSP Failure Response;
          'response-error'= Total OCSP Error Response; 'response-timeout'= Total OCSP
          Timeout Response; 'response-other'= Total OCSP Other Response; 'job-start-
          error'= Total OCSP Job Start Error; 'polling-control-error'= Total OCSP Polling
          Control Error;"
                type: str
    instance_list:
        description:
        - "Field instance_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify OCSP authentication server name"
                type: str
            url:
                description:
                - "Specify the OCSP server's address (Format= http=//host[=port]/) (The OCSP
          server's address(Format= http=//host[=port]/))"
                type: str
            responder_ca:
                description:
                - "Specify the trusted OCSP responder's CA cert filename"
                type: str
            responder_cert:
                description:
                - "Specify the trusted OCSP responder's cert filename"
                type: str
            health_check:
                description:
                - "Check server's health status"
                type: bool
            health_check_string:
                description:
                - "Health monitor name"
                type: str
            health_check_disable:
                description:
                - "Disable configured health check configuration"
                type: bool
            port_health_check:
                description:
                - "Check port's health status"
                type: str
            port_health_check_disable:
                description:
                - "Disable configured port health check configuration"
                type: bool
            http_version:
                description:
                - "Set HTTP version (default 1.0)"
                type: bool
            version_type:
                description:
                - "'1.1'= HTTP version 1.1;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            stapling_certificate_good:
                description:
                - "Total OCSP Stapling Good Certificate Response"
                type: str
            stapling_certificate_revoked:
                description:
                - "Total OCSP Stapling Revoked Certificate Response"
                type: str
            stapling_certificate_unknown:
                description:
                - "Total OCSP Stapling Unknown Certificate Response"
                type: str
            stapling_request_normal:
                description:
                - "Total OSCP Stapling Normal Request"
                type: str
            stapling_request_dropped:
                description:
                - "Total OCSP Stapling Dropped Request"
                type: str
            stapling_response_success:
                description:
                - "Total OCSP Stapling Success Response"
                type: str
            stapling_response_failure:
                description:
                - "Total OCSP Stapling Failure Response"
                type: str
            stapling_response_error:
                description:
                - "Total OCSP Stapling Error Response"
                type: str
            stapling_response_timeout:
                description:
                - "Total OCSP Stapling Timeout Response"
                type: str
            stapling_response_other:
                description:
                - "Total OCSP Stapling Other Response"
                type: str
            request_normal:
                description:
                - "Total OSCP Normal Request"
                type: str
            request_dropped:
                description:
                - "Total OCSP Dropped Request"
                type: str
            response_success:
                description:
                - "Total OCSP Success Response"
                type: str
            response_failure:
                description:
                - "Total OCSP Failure Response"
                type: str
            response_error:
                description:
                - "Total OCSP Error Response"
                type: str
            response_timeout:
                description:
                - "Total OCSP Timeout Response"
                type: str
            response_other:
                description:
                - "Total OCSP Other Response"
                type: str
            job_start_error:
                description:
                - "Total OCSP Job Start Error"
                type: str
            polling_control_error:
                description:
                - "Total OCSP Polling Control Error"
                type: str
            instance_list:
                description:
                - "Field instance_list"
                type: list

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
    "instance_list",
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
                    'all', 'stapling-certificate-good',
                    'stapling-certificate-revoked',
                    'stapling-certificate-unknown', 'stapling-request-normal',
                    'stapling-request-dropped', 'stapling-response-success',
                    'stapling-response-failure', 'stapling-response-error',
                    'stapling-response-timeout', 'stapling-response-other',
                    'request-normal', 'request-dropped', 'response-success',
                    'response-failure', 'response-error', 'response-timeout',
                    'response-other', 'job-start-error',
                    'polling-control-error'
                ]
            }
        },
        'instance_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'url': {
                'type': 'str',
            },
            'responder_ca': {
                'type': 'str',
            },
            'responder_cert': {
                'type': 'str',
            },
            'health_check': {
                'type': 'bool',
            },
            'health_check_string': {
                'type': 'str',
            },
            'health_check_disable': {
                'type': 'bool',
            },
            'port_health_check': {
                'type': 'str',
            },
            'port_health_check_disable': {
                'type': 'bool',
            },
            'http_version': {
                'type': 'bool',
            },
            'version_type': {
                'type': 'str',
                'choices': ['1.1']
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'request', 'certificate-good',
                        'certificate-revoked', 'certificate-unknown',
                        'timeout', 'fail', 'stapling-request',
                        'stapling-certificate-good',
                        'stapling-certificate-revoked',
                        'stapling-certificate-unknown', 'stapling-timeout',
                        'stapling-fail'
                    ]
                }
            }
        },
        'stats': {
            'type': 'dict',
            'stapling_certificate_good': {
                'type': 'str',
            },
            'stapling_certificate_revoked': {
                'type': 'str',
            },
            'stapling_certificate_unknown': {
                'type': 'str',
            },
            'stapling_request_normal': {
                'type': 'str',
            },
            'stapling_request_dropped': {
                'type': 'str',
            },
            'stapling_response_success': {
                'type': 'str',
            },
            'stapling_response_failure': {
                'type': 'str',
            },
            'stapling_response_error': {
                'type': 'str',
            },
            'stapling_response_timeout': {
                'type': 'str',
            },
            'stapling_response_other': {
                'type': 'str',
            },
            'request_normal': {
                'type': 'str',
            },
            'request_dropped': {
                'type': 'str',
            },
            'response_success': {
                'type': 'str',
            },
            'response_failure': {
                'type': 'str',
            },
            'response_error': {
                'type': 'str',
            },
            'response_timeout': {
                'type': 'str',
            },
            'response_other': {
                'type': 'str',
            },
            'job_start_error': {
                'type': 'str',
            },
            'polling_control_error': {
                'type': 'str',
            },
            'instance_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'request': {
                        'type': 'str',
                    },
                    'certificate_good': {
                        'type': 'str',
                    },
                    'certificate_revoked': {
                        'type': 'str',
                    },
                    'certificate_unknown': {
                        'type': 'str',
                    },
                    'timeout': {
                        'type': 'str',
                    },
                    'fail': {
                        'type': 'str',
                    },
                    'stapling_request': {
                        'type': 'str',
                    },
                    'stapling_certificate_good': {
                        'type': 'str',
                    },
                    'stapling_certificate_revoked': {
                        'type': 'str',
                    },
                    'stapling_certificate_unknown': {
                        'type': 'str',
                    },
                    'stapling_timeout': {
                        'type': 'str',
                    },
                    'stapling_fail': {
                        'type': 'str',
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/ocsp"

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
    url_base = "/axapi/v3/aam/authentication/server/ocsp"

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
        for k, v in payload["ocsp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ocsp"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ocsp"][k] = v
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
    payload = build_json("ocsp", module)
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
