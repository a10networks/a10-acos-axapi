#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_server_ssl
description:
    - Server Side SSL Template
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
        - "Server SSL Template Name"
        type: str
        required: True
    ca_certs:
        description:
        - "Field ca_certs"
        type: list
        required: False
        suboptions:
            ca_cert:
                description:
                - "Specify CA certificate"
                type: str
            ca_cert_partition_shared:
                description:
                - "CA Certificate Partition Shared"
                type: bool
            server_ocsp_srvr:
                description:
                - "Specify authentication server"
                type: str
            server_ocsp_sg:
                description:
                - "Specify service-group (Service group name)"
                type: str
    server_name:
        description:
        - "Specify Server Name"
        type: str
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        type: list
        required: False
        suboptions:
            crl:
                description:
                - "Certificate Revocation Lists (Certificate Revocation Lists file name)"
                type: str
            crl_partition_shared:
                description:
                - "Certificate Revocation Lists Partition Shared"
                type: bool
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        type: list
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "'SSL3_RSA_DES_192_CBC3_SHA'= TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A);
          'SSL3_RSA_RC4_128_MD5'= TLS_RSA_WITH_RC4_128_MD5 (0x0004);
          'SSL3_RSA_RC4_128_SHA'= TLS_RSA_WITH_RC4_128_SHA (0x0005);
          'TLS1_RSA_AES_128_SHA'= TLS_RSA_WITH_AES_128_CBC_SHA (0x002F);
          'TLS1_RSA_AES_256_SHA'= TLS_RSA_WITH_AES_256_CBC_SHA (0x0035);
          'TLS1_RSA_AES_128_SHA256'= TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C);
          'TLS1_RSA_AES_256_SHA256'= TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D);
          'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
          (0x009E); 'TLS1_DHE_RSA_AES_128_SHA'= TLS_DHE_RSA_WITH_AES_128_CBC_SHA
          (0x0033); 'TLS1_DHE_RSA_AES_128_SHA256'= TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
          (0x0067); 'TLS1_DHE_RSA_AES_256_GCM_SHA384'=
          TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009F); 'TLS1_DHE_RSA_AES_256_SHA'=
          TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039); 'TLS1_DHE_RSA_AES_256_SHA256'=
          TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006B);
          'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
          (0xC02B); 'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
          (0xC009); 'TLS1_ECDHE_ECDSA_AES_128_SHA256'=
          TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023);
          'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
          (0xC02C); 'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
          (0xC00A); 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'=
          TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F); 'TLS1_ECDHE_RSA_AES_128_SHA'=
          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013); 'TLS1_ECDHE_RSA_AES_128_SHA256'=
          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027);
          'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          (0xC030); 'TLS1_ECDHE_RSA_AES_256_SHA'= TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
          (0xC014); 'TLS1_RSA_AES_128_GCM_SHA256'= TLS_RSA_WITH_AES_128_GCM_SHA256
          (0x009C); 'TLS1_RSA_AES_256_GCM_SHA384'= TLS_RSA_WITH_AES_256_GCM_SHA384
          (0x009D); 'TLS1_ECDHE_RSA_AES_256_SHA384'=
          TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028);
          'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
          (0xC024); 'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8);
          'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256'=
          TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9);
          'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCAA);"
                type: str
    dh_type:
        description:
        - "'1024'= 1024; '1024-dsa'= 1024-dsa; '2048'= 2048;"
        type: str
        required: False
    ec_list:
        description:
        - "Field ec_list"
        type: list
        required: False
        suboptions:
            ec:
                description:
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1; 'secp521r1'= secp521r1;
          'x25519'= x25519;"
                type: str
    enable_tls_alert_logging:
        description:
        - "Enable TLS alert logging"
        type: bool
        required: False
    alert_type:
        description:
        - "'fatal'= Log fatal alerts;"
        type: str
        required: False
    handshake_logging_enable:
        description:
        - "Enable SSL handshake logging"
        type: bool
        required: False
    close_notify:
        description:
        - "Send close notification when terminate connection"
        type: bool
        required: False
    forward_proxy_enable:
        description:
        - "Enable SSL forward proxy"
        type: bool
        required: False
    session_ticket_enable:
        description:
        - "Enable server side session ticket support"
        type: bool
        required: False
    version:
        description:
        - "TLS/SSL version, default is the highest number supported (TLS/SSL version=
          30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1, 33-TLSv1.2 and 34-TLSv1.3)"
        type: int
        required: False
    dgversion:
        description:
        - "Lower TLS/SSL version can be downgraded"
        type: int
        required: False
    server_certificate_error:
        description:
        - "Field server_certificate_error"
        type: list
        required: False
        suboptions:
            error_type:
                description:
                - "'email'= Notify the error via email; 'ignore'= Ignore the error, which mean the
          connection can continue; 'logging'= Log the error; 'trap'= Notify the error by
          SNMP trap;"
                type: str
    ssli_logging:
        description:
        - "SSLi logging level, default is error logging only"
        type: bool
        required: False
    sslilogging:
        description:
        - "'disable'= Disable all logging; 'all'= enable all logging(error, info);"
        type: str
        required: False
    ocsp_stapling:
        description:
        - "Enable ocsp-stapling support"
        type: bool
        required: False
    use_client_sni:
        description:
        - "use client SNI"
        type: bool
        required: False
    renegotiation_disable:
        description:
        - "Disable SSL renegotiation"
        type: bool
        required: False
    session_cache_size:
        description:
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse
          disabled))"
        type: int
        required: False
    session_cache_timeout:
        description:
        - "Session Cache Timeout (Timeout value, in seconds. Default no timeout.)"
        type: int
        required: False
    cipher_template:
        description:
        - "Cipher Template Name"
        type: str
        required: False
    shared_partition_cipher_template:
        description:
        - "Reference a cipher template from shared partition"
        type: bool
        required: False
    template_cipher_shared:
        description:
        - "Cipher Template Name"
        type: str
        required: False
    enable_ssli_ftp_alg:
        description:
        - "Enable SSLi FTP over TLS support at which port"
        type: int
        required: False
    early_data:
        description:
        - "Enable TLS 1.3 early data (0-RTT)"
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
    certificate:
        description:
        - "Field certificate"
        type: dict
        required: False
        suboptions:
            cert:
                description:
                - "Certificate Name"
                type: str
            key:
                description:
                - "Client private-key (Key Name)"
                type: str
            passphrase:
                description:
                - "Password Phrase"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
            shared:
                description:
                - "Client Certificate and Key Partition Shared"
                type: bool
            uuid:
                description:
                - "uuid of the object"
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
    "alert_type", "ca_certs", "certificate", "cipher_template", "cipher_without_prio_list", "close_notify", "crl_certs", "dgversion", "dh_type", "early_data", "ec_list", "enable_ssli_ftp_alg", "enable_tls_alert_logging", "forward_proxy_enable", "handshake_logging_enable", "name", "ocsp_stapling", "renegotiation_disable", "server_certificate_error",
    "server_name", "session_cache_size", "session_cache_timeout", "session_ticket_enable", "shared_partition_cipher_template", "ssli_logging", "sslilogging", "template_cipher_shared", "use_client_sni", "user_tag", "uuid", "version",
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
        'ca_certs': {
            'type': 'list',
            'ca_cert': {
                'type': 'str',
                },
            'ca_cert_partition_shared': {
                'type': 'bool',
                },
            'server_ocsp_srvr': {
                'type': 'str',
                },
            'server_ocsp_sg': {
                'type': 'str',
                }
            },
        'server_name': {
            'type': 'str',
            },
        'crl_certs': {
            'type': 'list',
            'crl': {
                'type': 'str',
                },
            'crl_partition_shared': {
                'type': 'bool',
                }
            },
        'cipher_without_prio_list': {
            'type': 'list',
            'cipher_wo_prio': {
                'type':
                'str',
                'choices': [
                    'SSL3_RSA_DES_192_CBC3_SHA', 'SSL3_RSA_RC4_128_MD5', 'SSL3_RSA_RC4_128_SHA', 'TLS1_RSA_AES_128_SHA', 'TLS1_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_SHA256', 'TLS1_RSA_AES_256_SHA256', 'TLS1_DHE_RSA_AES_128_GCM_SHA256', 'TLS1_DHE_RSA_AES_128_SHA', 'TLS1_DHE_RSA_AES_128_SHA256', 'TLS1_DHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_DHE_RSA_AES_256_SHA', 'TLS1_DHE_RSA_AES_256_SHA256', 'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256', 'TLS1_ECDHE_ECDSA_AES_128_SHA', 'TLS1_ECDHE_ECDSA_AES_128_SHA256', 'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_ECDSA_AES_256_SHA', 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256', 'TLS1_ECDHE_RSA_AES_128_SHA',
                    'TLS1_ECDHE_RSA_AES_128_SHA256', 'TLS1_ECDHE_RSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_GCM_SHA256', 'TLS1_RSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_RSA_AES_256_SHA384', 'TLS1_ECDHE_ECDSA_AES_256_SHA384', 'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256', 'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'
                    ]
                }
            },
        'dh_type': {
            'type': 'str',
            'choices': ['1024', '1024-dsa', '2048']
            },
        'ec_list': {
            'type': 'list',
            'ec': {
                'type': 'str',
                'choices': ['secp256r1', 'secp384r1', 'secp521r1', 'x25519']
                }
            },
        'enable_tls_alert_logging': {
            'type': 'bool',
            },
        'alert_type': {
            'type': 'str',
            'choices': ['fatal']
            },
        'handshake_logging_enable': {
            'type': 'bool',
            },
        'close_notify': {
            'type': 'bool',
            },
        'forward_proxy_enable': {
            'type': 'bool',
            },
        'session_ticket_enable': {
            'type': 'bool',
            },
        'version': {
            'type': 'int',
            },
        'dgversion': {
            'type': 'int',
            },
        'server_certificate_error': {
            'type': 'list',
            'error_type': {
                'type': 'str',
                'choices': ['email', 'ignore', 'logging', 'trap']
                }
            },
        'ssli_logging': {
            'type': 'bool',
            },
        'sslilogging': {
            'type': 'str',
            'choices': ['disable', 'all']
            },
        'ocsp_stapling': {
            'type': 'bool',
            },
        'use_client_sni': {
            'type': 'bool',
            },
        'renegotiation_disable': {
            'type': 'bool',
            },
        'session_cache_size': {
            'type': 'int',
            },
        'session_cache_timeout': {
            'type': 'int',
            },
        'cipher_template': {
            'type': 'str',
            },
        'shared_partition_cipher_template': {
            'type': 'bool',
            },
        'template_cipher_shared': {
            'type': 'str',
            },
        'enable_ssli_ftp_alg': {
            'type': 'int',
            },
        'early_data': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'certificate': {
            'type': 'dict',
            'cert': {
                'type': 'str',
                },
            'key': {
                'type': 'str',
                },
            'passphrase': {
                'type': 'str',
                },
            'encrypted': {
                'type': 'str',
                },
            'shared': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server-ssl/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/server-ssl"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["server-ssl"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["server-ssl"].get(k) != v:
            change_results["changed"] = True
            config_changes["server-ssl"][k] = v

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
    payload = utils.build_json("server-ssl", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["server-ssl"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["server-ssl-list"] if info != "NotFound" else info
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
