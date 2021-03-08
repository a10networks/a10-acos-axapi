#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_server_windows_instance
description:
    - 'Windows Server, using Kerberos or NTLM for authentication'
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
        - "Specify Windows authentication server name"
        type: str
        required: True
    host:
        description:
        - "Field host"
        type: dict
        required: False
        suboptions:
            hostip:
                description:
                - "Specify the Windows server's hostname(Length 1-31) or IP address"
                type: str
            hostipv6:
                description:
                - "Specify the Windows server's IPV6 address"
                type: str
    timeout:
        description:
        - "Specify connection timeout to server, default is 10 seconds"
        type: int
        required: False
    auth_protocol:
        description:
        - "Field auth_protocol"
        type: dict
        required: False
        suboptions:
            ntlm_disable:
                description:
                - "Disable NTLM authentication protocol"
                type: bool
            ntlm_version:
                description:
                - "Specify NTLM version, default is 2"
                type: int
            ntlm_health_check:
                description:
                - "Check NTLM port's health status"
                type: str
            ntlm_health_check_disable:
                description:
                - "Disable configured NTLM port health check configuration"
                type: bool
            kerberos_disable:
                description:
                - "Disable Kerberos authentication protocol"
                type: bool
            kerberos_port:
                description:
                - "Specify the Kerberos port, default is 88"
                type: int
            kport_hm:
                description:
                - "Check Kerberos port's health status"
                type: str
            kport_hm_disable:
                description:
                - "Disable configured Kerberos port health check configuration"
                type: bool
            kerberos_password_change_port:
                description:
                - "Specify the Kerbros password change port, default is 464"
                type: int
    realm:
        description:
        - "Specify realm of Windows server"
        type: str
        required: False
    support_apacheds_kdc:
        description:
        - "Enable weak cipher (DES CRC/MD5/MD4) and merge AS-REQ in single packet"
        type: bool
        required: False
    health_check:
        description:
        - "Check server's health status"
        type: bool
        required: False
    health_check_string:
        description:
        - "Health monitor name"
        type: str
        required: False
    health_check_disable:
        description:
        - "Disable configured health check configuration"
        type: bool
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
                - "'all'= all; 'krb_send_req_success'= Kerberos Request; 'krb_get_resp_success'=
          Kerberos Response; 'krb_timeout_error'= Kerberos Timeout; 'krb_other_error'=
          Kerberos Other Error; 'krb_pw_expiry'= Kerberos password expiry;
          'krb_pw_change_success'= Kerberos password change success;
          'krb_pw_change_failure'= Kerberos password change failure;
          'ntlm_proto_nego_success'= NTLM Protocol Negotiation Success;
          'ntlm_proto_nego_failure'= NTLM Protocol Negotiation Failure;
          'ntlm_session_setup_success'= NTLM Session Setup Success;
          'ntlm_session_setup_failure'= NTLM Session Setup Failure;
          'ntlm_prepare_req_success'= NTLM Prepare Request Success;
          'ntlm_prepare_req_error'= NTLM Prepare Request Error; 'ntlm_auth_success'= NTLM
          Authentication Success; 'ntlm_auth_failure'= NTLM Authentication Failure;
          'ntlm_timeout_error'= NTLM Timeout; 'ntlm_other_error'= NTLM Other Error;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            krb_send_req_success:
                description:
                - "Kerberos Request"
                type: str
            krb_get_resp_success:
                description:
                - "Kerberos Response"
                type: str
            krb_timeout_error:
                description:
                - "Kerberos Timeout"
                type: str
            krb_other_error:
                description:
                - "Kerberos Other Error"
                type: str
            krb_pw_expiry:
                description:
                - "Kerberos password expiry"
                type: str
            krb_pw_change_success:
                description:
                - "Kerberos password change success"
                type: str
            krb_pw_change_failure:
                description:
                - "Kerberos password change failure"
                type: str
            ntlm_proto_nego_success:
                description:
                - "NTLM Protocol Negotiation Success"
                type: str
            ntlm_proto_nego_failure:
                description:
                - "NTLM Protocol Negotiation Failure"
                type: str
            ntlm_session_setup_success:
                description:
                - "NTLM Session Setup Success"
                type: str
            ntlm_session_setup_failure:
                description:
                - "NTLM Session Setup Failure"
                type: str
            ntlm_prepare_req_success:
                description:
                - "NTLM Prepare Request Success"
                type: str
            ntlm_prepare_req_error:
                description:
                - "NTLM Prepare Request Error"
                type: str
            ntlm_auth_success:
                description:
                - "NTLM Authentication Success"
                type: str
            ntlm_auth_failure:
                description:
                - "NTLM Authentication Failure"
                type: str
            ntlm_timeout_error:
                description:
                - "NTLM Timeout"
                type: str
            ntlm_other_error:
                description:
                - "NTLM Other Error"
                type: str
            name:
                description:
                - "Specify Windows authentication server name"
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
    "auth_protocol",
    "health_check",
    "health_check_disable",
    "health_check_string",
    "host",
    "name",
    "realm",
    "sampling_enable",
    "stats",
    "support_apacheds_kdc",
    "timeout",
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
        'host': {
            'type': 'dict',
            'hostip': {
                'type': 'str',
            },
            'hostipv6': {
                'type': 'str',
            }
        },
        'timeout': {
            'type': 'int',
        },
        'auth_protocol': {
            'type': 'dict',
            'ntlm_disable': {
                'type': 'bool',
            },
            'ntlm_version': {
                'type': 'int',
            },
            'ntlm_health_check': {
                'type': 'str',
            },
            'ntlm_health_check_disable': {
                'type': 'bool',
            },
            'kerberos_disable': {
                'type': 'bool',
            },
            'kerberos_port': {
                'type': 'int',
            },
            'kport_hm': {
                'type': 'str',
            },
            'kport_hm_disable': {
                'type': 'bool',
            },
            'kerberos_password_change_port': {
                'type': 'int',
            }
        },
        'realm': {
            'type': 'str',
        },
        'support_apacheds_kdc': {
            'type': 'bool',
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'krb_send_req_success', 'krb_get_resp_success',
                    'krb_timeout_error', 'krb_other_error', 'krb_pw_expiry',
                    'krb_pw_change_success', 'krb_pw_change_failure',
                    'ntlm_proto_nego_success', 'ntlm_proto_nego_failure',
                    'ntlm_session_setup_success', 'ntlm_session_setup_failure',
                    'ntlm_prepare_req_success', 'ntlm_prepare_req_error',
                    'ntlm_auth_success', 'ntlm_auth_failure',
                    'ntlm_timeout_error', 'ntlm_other_error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'krb_send_req_success': {
                'type': 'str',
            },
            'krb_get_resp_success': {
                'type': 'str',
            },
            'krb_timeout_error': {
                'type': 'str',
            },
            'krb_other_error': {
                'type': 'str',
            },
            'krb_pw_expiry': {
                'type': 'str',
            },
            'krb_pw_change_success': {
                'type': 'str',
            },
            'krb_pw_change_failure': {
                'type': 'str',
            },
            'ntlm_proto_nego_success': {
                'type': 'str',
            },
            'ntlm_proto_nego_failure': {
                'type': 'str',
            },
            'ntlm_session_setup_success': {
                'type': 'str',
            },
            'ntlm_session_setup_failure': {
                'type': 'str',
            },
            'ntlm_prepare_req_success': {
                'type': 'str',
            },
            'ntlm_prepare_req_error': {
                'type': 'str',
            },
            'ntlm_auth_success': {
                'type': 'str',
            },
            'ntlm_auth_failure': {
                'type': 'str',
            },
            'ntlm_timeout_error': {
                'type': 'str',
            },
            'ntlm_other_error': {
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
    url_base = "/axapi/v3/aam/authentication/server/windows/instance/{name}"

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
    url_base = "/axapi/v3/aam/authentication/server/windows/instance/{name}"

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
        for k, v in payload["instance"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["instance"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["instance"][k] = v
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
    payload = build_json("instance", module)
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
