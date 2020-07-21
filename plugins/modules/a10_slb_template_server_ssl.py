#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_server_ssl
description:
    - Server Side SSL Template
short_description: Configures A10 slb.template.server-ssl
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    session_cache_timeout:
        description:
        - "Session Cache Timeout (Timeout value, in seconds. Default no timeout.)"
        required: False
    cipher_template:
        description:
        - "Cipher Template Name"
        required: False
    sslilogging:
        description:
        - "'disable'= Disable all logging; 'all'= enable all logging(error, info);"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    passphrase:
        description:
        - "Password Phrase"
        required: False
    ocsp_stapling:
        description:
        - "Enable ocsp-stapling support"
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        required: False
        suboptions:
            crl:
                description:
                - "Certificate Revocation Lists (Certificate Revocation Lists file name)"
    uuid:
        description:
        - "uuid of the object"
        required: False
    key_shared_str:
        description:
        - "Key Name"
        required: False
    template_cipher_shared:
        description:
        - "Cipher Template Name"
        required: False
    dgversion:
        description:
        - "Lower TLS/SSL version can be downgraded"
        required: False
    cert_shared_str:
        description:
        - "Certificate Name"
        required: False
    version:
        description:
        - "TLS/SSL version, default is the highest number supported (TLS/SSL version=
          30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)"
        required: False
    ec_list:
        description:
        - "Field ec_list"
        required: False
        suboptions:
            ec:
                description:
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1;"
    encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    ssli_logging:
        description:
        - "SSLi logging level, default is error logging only"
        required: False
    session_cache_size:
        description:
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse
          disabled))"
        required: False
    dh_type:
        description:
        - "'1024'= 1024; '1024-dsa'= 1024-dsa; '2048'= 2048;"
        required: False
    use_client_sni:
        description:
        - "use client SNI"
        required: False
    forward_proxy_enable:
        description:
        - "Enable SSL forward proxy"
        required: False
    key:
        description:
        - "Key Name"
        required: False
    key_shared_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "'SSL3_RSA_DES_192_CBC3_SHA'= SSL3_RSA_DES_192_CBC3_SHA; 'SSL3_RSA_RC4_128_MD5'=
          SSL3_RSA_RC4_128_MD5; 'SSL3_RSA_RC4_128_SHA'= SSL3_RSA_RC4_128_SHA;
          'TLS1_RSA_AES_128_SHA'= TLS1_RSA_AES_128_SHA; 'TLS1_RSA_AES_256_SHA'=
          TLS1_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_SHA256'= TLS1_RSA_AES_128_SHA256;
          'TLS1_RSA_AES_256_SHA256'= TLS1_RSA_AES_256_SHA256;
          'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS1_DHE_RSA_AES_128_GCM_SHA256;
          'TLS1_DHE_RSA_AES_128_SHA'= TLS1_DHE_RSA_AES_128_SHA;
          'TLS1_DHE_RSA_AES_128_SHA256'= TLS1_DHE_RSA_AES_128_SHA256;
          'TLS1_DHE_RSA_AES_256_GCM_SHA384'= TLS1_DHE_RSA_AES_256_GCM_SHA384;
          'TLS1_DHE_RSA_AES_256_SHA'= TLS1_DHE_RSA_AES_256_SHA;
          'TLS1_DHE_RSA_AES_256_SHA256'= TLS1_DHE_RSA_AES_256_SHA256;
          'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256;
          'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS1_ECDHE_ECDSA_AES_128_SHA;
          'TLS1_ECDHE_ECDSA_AES_128_SHA256'= TLS1_ECDHE_ECDSA_AES_128_SHA256;
          'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS1_ECDHE_ECDSA_AES_256_SHA;
          'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'= TLS1_ECDHE_RSA_AES_128_GCM_SHA256;
          'TLS1_ECDHE_RSA_AES_128_SHA'= TLS1_ECDHE_RSA_AES_128_SHA;
          'TLS1_ECDHE_RSA_AES_128_SHA256'= TLS1_ECDHE_RSA_AES_128_SHA256;
          'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS1_ECDHE_RSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_RSA_AES_256_SHA'= TLS1_ECDHE_RSA_AES_256_SHA;
          'TLS1_RSA_AES_128_GCM_SHA256'= TLS1_RSA_AES_128_GCM_SHA256;
          'TLS1_RSA_AES_256_GCM_SHA384'= TLS1_RSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_RSA_AES_256_SHA384'= TLS1_ECDHE_RSA_AES_256_SHA384;
          'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS1_ECDHE_ECDSA_AES_256_SHA384;
          'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256;
          'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256'=
          TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256;
          'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'= TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256;"
    ca_certs:
        description:
        - "Field ca_certs"
        required: False
        suboptions:
            ca_cert:
                description:
                - "Specify CA certificate"
            ca_cert_partition_shared:
                description:
                - "CA Certificate Partition Shared"
            server_ocsp_sg:
                description:
                - "Specify service-group (Service group name)"
            server_ocsp_srvr:
                description:
                - "Specify authentication server"
    name:
        description:
        - "Server SSL Template Name"
        required: True
    shared_partition_cipher_template:
        description:
        - "Reference a cipher template from shared partition"
        required: False
    enable_tls_alert_logging:
        description:
        - "Enable TLS alert logging"
        required: False
    session_ticket_enable:
        description:
        - "Enable server side session ticket support"
        required: False
    alert_type:
        description:
        - "'fatal'= Log fatal alerts;"
        required: False
    cert:
        description:
        - "Certificate Name"
        required: False
    handshake_logging_enable:
        description:
        - "Enable SSL handshake logging"
        required: False
    renegotiation_disable:
        description:
        - "Disable SSL renegotiation"
        required: False
    server_certificate_error:
        description:
        - "Field server_certificate_error"
        required: False
        suboptions:
            error_type:
                description:
                - "'email'= Notify the error via email; 'ignore'= Ignore the error, which mean the
          connection can continue; 'logging'= Log the error; 'trap'= Notify the error by
          SNMP trap;"
    close_notify:
        description:
        - "Send close notification when terminate connection"
        required: False
    key_shared_passphrase:
        description:
        - "Password Phrase"
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
AVAILABLE_PROPERTIES = [
    "alert_type",
    "ca_certs",
    "cert",
    "cert_shared_str",
    "cipher_template",
    "cipher_without_prio_list",
    "close_notify",
    "crl_certs",
    "dgversion",
    "dh_type",
    "ec_list",
    "enable_tls_alert_logging",
    "encrypted",
    "forward_proxy_enable",
    "handshake_logging_enable",
    "key",
    "key_shared_encrypted",
    "key_shared_passphrase",
    "key_shared_str",
    "name",
    "ocsp_stapling",
    "passphrase",
    "renegotiation_disable",
    "server_certificate_error",
    "session_cache_size",
    "session_cache_timeout",
    "session_ticket_enable",
    "shared_partition_cipher_template",
    "ssli_logging",
    "sslilogging",
    "template_cipher_shared",
    "use_client_sni",
    "user_tag",
    "uuid",
    "version",
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
        'session_cache_timeout': {
            'type': 'int',
        },
        'cipher_template': {
            'type': 'str',
        },
        'sslilogging': {
            'type': 'str',
            'choices': ['disable', 'all']
        },
        'user_tag': {
            'type': 'str',
        },
        'passphrase': {
            'type': 'str',
        },
        'ocsp_stapling': {
            'type': 'bool',
        },
        'crl_certs': {
            'type': 'list',
            'crl': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'key_shared_str': {
            'type': 'str',
        },
        'template_cipher_shared': {
            'type': 'str',
        },
        'dgversion': {
            'type': 'int',
        },
        'cert_shared_str': {
            'type': 'str',
        },
        'version': {
            'type': 'int',
        },
        'ec_list': {
            'type': 'list',
            'ec': {
                'type': 'str',
                'choices': ['secp256r1', 'secp384r1']
            }
        },
        'encrypted': {
            'type': 'str',
        },
        'ssli_logging': {
            'type': 'bool',
        },
        'session_cache_size': {
            'type': 'int',
        },
        'dh_type': {
            'type': 'str',
            'choices': ['1024', '1024-dsa', '2048']
        },
        'use_client_sni': {
            'type': 'bool',
        },
        'forward_proxy_enable': {
            'type': 'bool',
        },
        'key': {
            'type': 'str',
        },
        'key_shared_encrypted': {
            'type': 'str',
        },
        'cipher_without_prio_list': {
            'type': 'list',
            'cipher_wo_prio': {
                'type':
                'str',
                'choices': [
                    'SSL3_RSA_DES_192_CBC3_SHA', 'SSL3_RSA_RC4_128_MD5',
                    'SSL3_RSA_RC4_128_SHA', 'TLS1_RSA_AES_128_SHA',
                    'TLS1_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_SHA256',
                    'TLS1_RSA_AES_256_SHA256',
                    'TLS1_DHE_RSA_AES_128_GCM_SHA256',
                    'TLS1_DHE_RSA_AES_128_SHA', 'TLS1_DHE_RSA_AES_128_SHA256',
                    'TLS1_DHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_DHE_RSA_AES_256_SHA', 'TLS1_DHE_RSA_AES_256_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_128_SHA',
                    'TLS1_ECDHE_ECDSA_AES_128_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_ECDSA_AES_256_SHA',
                    'TLS1_ECDHE_RSA_AES_128_GCM_SHA256',
                    'TLS1_ECDHE_RSA_AES_128_SHA',
                    'TLS1_ECDHE_RSA_AES_128_SHA256',
                    'TLS1_ECDHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_RSA_AES_256_SHA',
                    'TLS1_RSA_AES_128_GCM_SHA256',
                    'TLS1_RSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_RSA_AES_256_SHA384',
                    'TLS1_ECDHE_ECDSA_AES_256_SHA384',
                    'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'
                ]
            }
        },
        'ca_certs': {
            'type': 'list',
            'ca_cert': {
                'type': 'str',
            },
            'ca_cert_partition_shared': {
                'type': 'bool',
            },
            'server_ocsp_sg': {
                'type': 'str',
            },
            'server_ocsp_srvr': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'shared_partition_cipher_template': {
            'type': 'bool',
        },
        'enable_tls_alert_logging': {
            'type': 'bool',
        },
        'session_ticket_enable': {
            'type': 'bool',
        },
        'alert_type': {
            'type': 'str',
            'choices': ['fatal']
        },
        'cert': {
            'type': 'str',
        },
        'handshake_logging_enable': {
            'type': 'bool',
        },
        'renegotiation_disable': {
            'type': 'bool',
        },
        'server_certificate_error': {
            'type': 'list',
            'error_type': {
                'type': 'str',
                'choices': ['email', 'ignore', 'logging', 'trap']
            }
        },
        'close_notify': {
            'type': 'bool',
        },
        'key_shared_passphrase': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server-ssl/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/slb/template/server-ssl/{name}"

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
        for k, v in payload["server-ssl"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["server-ssl"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["server-ssl"][k] = v
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
    payload = build_json("server-ssl", module)
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
