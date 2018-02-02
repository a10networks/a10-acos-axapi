#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_server_ssl
description:
    - None
short_description: Configures A10 slb.template.server-ssl
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
    ca_certs:
        description:
        - "Field ca_certs"
        required: False
        suboptions:
            ca_cert:
                description:
                - "None"
            server_ocsp_srvr:
                description:
                - "None"
            server_ocsp_sg:
                description:
                - "None"
    crl_certs:
        description:
        - "Field crl_certs"
        required: False
        suboptions:
            crl:
                description:
                - "None"
    cert:
        description:
        - "None"
        required: False
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "None"
    dh_type:
        description:
        - "None"
        required: False
    ec_list:
        description:
        - "Field ec_list"
        required: False
        suboptions:
            ec:
                description:
                - "None"
    enable_tls_alert_logging:
        description:
        - "None"
        required: False
    alert_type:
        description:
        - "None"
        required: False
    handshake_logging_enable:
        description:
        - "None"
        required: False
    close_notify:
        description:
        - "None"
        required: False
    forward_proxy_enable:
        description:
        - "None"
        required: False
    session_ticket_enable:
        description:
        - "None"
        required: False
    version:
        description:
        - "None"
        required: False
    dgversion:
        description:
        - "None"
        required: False
    server_certificate_error:
        description:
        - "Field server_certificate_error"
        required: False
        suboptions:
            error_type:
                description:
                - "None"
    ssli_logging:
        description:
        - "None"
        required: False
    sslilogging:
        description:
        - "None"
        required: False
    key:
        description:
        - "None"
        required: False
    passphrase:
        description:
        - "None"
        required: False
    encrypted:
        description:
        - "None"
        required: False
    ocsp_stapling:
        description:
        - "None"
        required: False
    use_client_sni:
        description:
        - "None"
        required: False
    renegotiation_disable:
        description:
        - "None"
        required: False
    session_cache_size:
        description:
        - "None"
        required: False
    session_cache_timeout:
        description:
        - "None"
        required: False
    cipher_template:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    user_tag:
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
AVAILABLE_PROPERTIES = ["alert_type","ca_certs","cert","cipher_template","cipher_without_prio_list","close_notify","crl_certs","dgversion","dh_type","ec_list","enable_tls_alert_logging","encrypted","forward_proxy_enable","handshake_logging_enable","key","name","ocsp_stapling","passphrase","renegotiation_disable","server_certificate_error","session_cache_size","session_cache_timeout","session_ticket_enable","ssli_logging","sslilogging","use_client_sni","user_tag","uuid","version",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory
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
        ca_certs=dict(type='list',ca_cert=dict(type='str',),server_ocsp_srvr=dict(type='str',),server_ocsp_sg=dict(type='str',)),
        crl_certs=dict(type='list',crl=dict(type='str',)),
        cert=dict(type='str',),
        cipher_without_prio_list=dict(type='list',cipher_wo_prio=dict(type='str',choices=['SSL3_RSA_DES_192_CBC3_SHA','SSL3_RSA_RC4_128_MD5','SSL3_RSA_RC4_128_SHA','TLS1_RSA_AES_128_SHA','TLS1_RSA_AES_256_SHA','TLS1_RSA_AES_128_SHA256','TLS1_RSA_AES_256_SHA256','TLS1_DHE_RSA_AES_128_GCM_SHA256','TLS1_DHE_RSA_AES_128_SHA','TLS1_DHE_RSA_AES_128_SHA256','TLS1_DHE_RSA_AES_256_GCM_SHA384','TLS1_DHE_RSA_AES_256_SHA','TLS1_DHE_RSA_AES_256_SHA256','TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256','TLS1_ECDHE_ECDSA_AES_128_SHA','TLS1_ECDHE_ECDSA_AES_128_SHA256','TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA','TLS1_ECDHE_RSA_AES_128_GCM_SHA256','TLS1_ECDHE_RSA_AES_128_SHA','TLS1_ECDHE_RSA_AES_128_SHA256','TLS1_ECDHE_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA','TLS1_RSA_AES_128_GCM_SHA256','TLS1_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA384'])),
        dh_type=dict(type='str',choices=['1024','1024-dsa','2048']),
        ec_list=dict(type='list',ec=dict(type='str',choices=['secp256r1','secp384r1'])),
        enable_tls_alert_logging=dict(type='bool',),
        alert_type=dict(type='str',choices=['fatal']),
        handshake_logging_enable=dict(type='bool',),
        close_notify=dict(type='bool',),
        forward_proxy_enable=dict(type='bool',),
        session_ticket_enable=dict(type='bool',),
        version=dict(type='int',),
        dgversion=dict(type='int',),
        server_certificate_error=dict(type='list',error_type=dict(type='str',choices=['email','ignore','logging','trap'])),
        ssli_logging=dict(type='bool',),
        sslilogging=dict(type='str',choices=['disable','all']),
        key=dict(type='str',),
        passphrase=dict(type='str',),
        encrypted=dict(type='str',),
        ocsp_stapling=dict(type='bool',),
        use_client_sni=dict(type='bool',),
        renegotiation_disable=dict(type='bool',),
        session_cache_size=dict(type='int',),
        session_cache_timeout=dict(type='int',),
        cipher_template=dict(type='str',),
        uuid=dict(type='str',),
        user_tag=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/server-ssl/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server-ssl/{name}"
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("server-ssl", module)
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

def update(module, result):
    payload = build_json("server-ssl", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

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

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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