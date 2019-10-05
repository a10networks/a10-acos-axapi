#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vpn_ike_gateway
description:
    - IKE-gateway settings
short_description: Configures A10 vpn.ike-gateway
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
    ike_version:
        description:
        - "'v1'= IKEv1 key exchange; 'v2'= IKEv2 key exchange; "
        required: False
    key_passphrase_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED key string)"
        required: False
    local_cert:
        description:
        - "Field local_cert"
        required: False
        suboptions:
            local_cert_name:
                description:
                - "Certificate File Name"
    lifetime:
        description:
        - "IKE SA age in seconds"
        required: False
    local_id:
        description:
        - "Local Gateway Identity"
        required: False
    enc_cfg:
        description:
        - "Field enc_cfg"
        required: False
        suboptions:
            priority:
                description:
                - "Prioritizes (1-10) security protocol, least value has highest priority"
            encryption:
                description:
                - "'des'= Data Encryption Standard algorithm; '3des'= Triple Data Encryption Standard algorithm; 'aes-128'= Advanced Encryption Standard algorithm CBC mode(key size= 128 bits); 'aes-192'= Advanced Encryption Standard algorithm CBC mode(key size= 192 bits); 'aes-256'= Advanced Encryption Standard algorithm CBC mode(key size= 256 bits); 'null'= No encryption algorithm, only for IKEv2; "
            hash:
                description:
                - "'md5'= MD5 Dessage-Digest Algorithm; 'sha1'= Secure Hash Algorithm 1; 'sha256'= Secure Hash Algorithm 256; 'sha384'= Secure Hash Algorithm 384; 'sha512'= Secure Hash Algorithm 512; "
    uuid:
        description:
        - "uuid of the object"
        required: False
    nat_traversal:
        description:
        - "Field nat_traversal"
        required: False
    vrid:
        description:
        - "Field vrid"
        required: False
        suboptions:
            vrid_num:
                description:
                - "Specify ha VRRP-A vrid"
    preshare_key_value:
        description:
        - "pre-shared key"
        required: False
    key_passphrase:
        description:
        - "Private Key Pass Phrase"
        required: False
    mode:
        description:
        - "'main'= Negotiate Main mode (Default); 'aggressive'= Negotiate Aggressive mode; "
        required: False
    local_address:
        description:
        - "Field local_address"
        required: False
        suboptions:
            local_ip:
                description:
                - "Ipv4 address"
            local_ipv6:
                description:
                - "Ipv6 address"
    key:
        description:
        - "Private Key"
        required: False
    preshare_key_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED pre-shared key string)"
        required: False
    remote_address:
        description:
        - "Field remote_address"
        required: False
        suboptions:
            remote_ip:
                description:
                - "Ipv4 address"
            dns:
                description:
                - "Remote IP based on Domain name"
            remote_ipv6:
                description:
                - "Ipv6 address"
    remote_ca_cert:
        description:
        - "Field remote_ca_cert"
        required: False
        suboptions:
            remote_cert_name:
                description:
                - "Remote CA certificate DN (C=, ST=, L=, O=, CN=) without emailAddress"
    name:
        description:
        - "IKE-gateway name"
        required: True
    dh_group:
        description:
        - "'1'= Diffie-Hellman group 1 - 768-bit(Default); '2'= Diffie-Hellman group 2 - 1024-bit; '5'= Diffie-Hellman group 5 - 1536-bit; '14'= Diffie-Hellman group 14 - 2048-bit; '15'= Diffie-Hellman group 15 - 3072-bit; '16'= Diffie-Hellman group 16 - 4096-bit; '18'= Diffie-Hellman group 18 - 8192-bit; '19'= Diffie-Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve; "
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'v2-init-rekey'= Initiate Rekey; 'v2-rsp-rekey'= Respond Rekey; 'v2-child-sa-rekey'= Child SA Rekey; 'v2-in-invalid'= Incoming Invalid; 'v2-in-invalid-spi'= Incoming Invalid SPI; 'v2-in-init-req'= Incoming Init Request; 'v2-in-init-rsp'= Incoming Init Response; 'v2-out-init-req'= Outgoing Init Request; 'v2-out-init-rsp'= Outgoing Init Response; 'v2-in-auth-req'= Incoming Auth Request; 'v2-in-auth-rsp'= Incoming Auth Response; 'v2-out-auth-req'= Outgoing Auth Request; 'v2-out-auth-rsp'= Outgoing Auth Response; 'v2-in-create-child-req'= Incoming Create Child Request; 'v2-in-create-child-rsp'= Incoming Create Child Response; 'v2-out-create-child-req'= Outgoing Create Child Request; 'v2-out-create-child-rsp'= Outgoing Create Child Response; 'v2-in-info-req'= Incoming Info Request; 'v2-in-info-rsp'= Incoming Info Response; 'v2-out-info-req'= Outgoing Info Request; 'v2-out-info-rsp'= Outgoing Info Response; 'v1-in-id-prot-req'= Incoming ID Protection Request; 'v1-in-id-prot-rsp'= Incoming ID Protection Response; 'v1-out-id-prot-req'= Outgoing ID Protection Request; 'v1-out-id-prot-rsp'= Outgoing ID Protection Response; 'v1-in-auth-only-req'= Incoming Auth Only Request; 'v1-in-auth-only-rsp'= Incoming Auth Only Response; 'v1-out-auth-only-req'= Outgoing Auth Only Request; 'v1-out-auth-only-rsp'= Outgoing Auth Only Response; 'v1-in-aggressive-req'= Incoming Aggressive Request; 'v1-in-aggressive-rsp'= Incoming Aggressive Response; 'v1-out-aggressive-req'= Outgoing Aggressive Request; 'v1-out-aggressive-rsp'= Outgoing Aggressive Response; 'v1-in-info-v1-req'= Incoming Info Request; 'v1-in-info-v1-rsp'= Incoming Info Response; 'v1-out-info-v1-req'= Outgoing Info Request; 'v1-out-info-v1-rsp'= Outgoing Info Response; 'v1-in-transaction-req'= Incoming Transaction Request; 'v1-in-transaction-rsp'= Incoming Transaction Response; 'v1-out-transaction-req'= Outgoing Transaction Request; 'v1-out-transaction-rsp'= Outgoing Transaction Response; 'v1-in-quick-mode-req'= Incoming Quick Mode Request; 'v1-in-quick-mode-rsp'= Incoming Quick Mode Response; 'v1-out-quick-mode-req'= Outgoing Quick Mode Request; 'v1-out-quick-mode-rsp'= Outgoing Quick Mode Response; 'v1-in-new-group-mode-req'= Incoming New Group Mode Request; 'v1-in-new-group-mode-rsp'= Incoming New Group Mode Response; 'v1-out-new-group-mode-req'= Outgoing New Group Mode Request; 'v1-out-new-group-mode-rsp'= Outgoing New Group Mode Response; 'v1-child-sa-invalid-spi'= Invalid SPI for Child SAs; 'v2-child-sa-invalid-spi'= Invalid SPI for Child SAs; 'ike-current-version'= IKE version; "
    dpd:
        description:
        - "Field dpd"
        required: False
        suboptions:
            interval:
                description:
                - "Interval time in seconds"
            retry:
                description:
                - "Retry times"
    remote_id:
        description:
        - "Remote Gateway Identity"
        required: False
    auth_method:
        description:
        - "'preshare-key'= Authenticate the remote gateway using a pre-shared key (Default); 'rsa-signature'= Authenticate the remote gateway using an RSA certificate; 'ecdsa-signature'= Authenticate the remote gateway using an ECDSA certificate; "
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
AVAILABLE_PROPERTIES = ["auth_method","dh_group","dpd","enc_cfg","ike_version","key","key_passphrase","key_passphrase_encrypted","lifetime","local_address","local_cert","local_id","mode","name","nat_traversal","preshare_key_encrypted","preshare_key_value","remote_address","remote_ca_cert","remote_id","sampling_enable","user_tag","uuid","vrid",]

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
        ike_version=dict(type='str',choices=['v1','v2']),
        key_passphrase_encrypted=dict(type='str',),
        local_cert=dict(type='dict',local_cert_name=dict(type='str',)),
        lifetime=dict(type='int',),
        local_id=dict(type='str',),
        enc_cfg=dict(type='list',priority=dict(type='int',),encryption=dict(type='str',choices=['des','3des','aes-128','aes-192','aes-256','null']),hash=dict(type='str',choices=['md5','sha1','sha256','sha384','sha512'])),
        uuid=dict(type='str',),
        nat_traversal=dict(type='bool',),
        vrid=dict(type='dict',vrid_num=dict(type='int',)),
        preshare_key_value=dict(type='str',),
        key_passphrase=dict(type='str',),
        mode=dict(type='str',choices=['main','aggressive']),
        local_address=dict(type='dict',local_ip=dict(type='str',),local_ipv6=dict(type='str',)),
        key=dict(type='str',),
        preshare_key_encrypted=dict(type='str',),
        remote_address=dict(type='dict',remote_ip=dict(type='str',),dns=dict(type='str',),remote_ipv6=dict(type='str',)),
        remote_ca_cert=dict(type='dict',remote_cert_name=dict(type='str',)),
        name=dict(type='str',required=True,),
        dh_group=dict(type='str',choices=['1','2','5','14','15','16','18','19','20']),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','v2-init-rekey','v2-rsp-rekey','v2-child-sa-rekey','v2-in-invalid','v2-in-invalid-spi','v2-in-init-req','v2-in-init-rsp','v2-out-init-req','v2-out-init-rsp','v2-in-auth-req','v2-in-auth-rsp','v2-out-auth-req','v2-out-auth-rsp','v2-in-create-child-req','v2-in-create-child-rsp','v2-out-create-child-req','v2-out-create-child-rsp','v2-in-info-req','v2-in-info-rsp','v2-out-info-req','v2-out-info-rsp','v1-in-id-prot-req','v1-in-id-prot-rsp','v1-out-id-prot-req','v1-out-id-prot-rsp','v1-in-auth-only-req','v1-in-auth-only-rsp','v1-out-auth-only-req','v1-out-auth-only-rsp','v1-in-aggressive-req','v1-in-aggressive-rsp','v1-out-aggressive-req','v1-out-aggressive-rsp','v1-in-info-v1-req','v1-in-info-v1-rsp','v1-out-info-v1-req','v1-out-info-v1-rsp','v1-in-transaction-req','v1-in-transaction-rsp','v1-out-transaction-req','v1-out-transaction-rsp','v1-in-quick-mode-req','v1-in-quick-mode-rsp','v1-out-quick-mode-req','v1-out-quick-mode-rsp','v1-in-new-group-mode-req','v1-in-new-group-mode-rsp','v1-out-new-group-mode-req','v1-out-new-group-mode-rsp','v1-child-sa-invalid-spi','v2-child-sa-invalid-spi','ike-current-version'])),
        dpd=dict(type='dict',interval=dict(type='int',),retry=dict(type='int',)),
        remote_id=dict(type='str',),
        auth_method=dict(type='str',choices=['preshare-key','rsa-signature','ecdsa-signature'])
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/ike-gateway/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/ike-gateway/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["ike-gateway"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["ike-gateway"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["ike-gateway"][k] = v
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
    payload = build_json("ike-gateway", module)
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

def replace(module, result, existing_config):
    payload = build_json("ike-gateway", module)
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