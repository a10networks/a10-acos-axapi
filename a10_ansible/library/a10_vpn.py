#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vpn
description:
    - VPN Commands
short_description: Configures A10 vpn
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
    jumbo_fragment:
        description:
        - "Support IKE jumbo fragment packet"
        required: False
    log:
        description:
        - "Field log"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    asymmetric_flow_support:
        description:
        - "Support asymmetric flows pass through IPsec tunnel"
        required: False
    default:
        description:
        - "Field default"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    ike_gateway_list:
        description:
        - "Field ike_gateway_list"
        required: False
        suboptions:
            ike_version:
                description:
                - "'v1'= IKEv1 key exchange; 'v2'= IKEv2 key exchange; "
            key_passphrase_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED key string)"
            local_cert:
                description:
                - "Field local_cert"
            lifetime:
                description:
                - "IKE SA age in seconds"
            local_id:
                description:
                - "Local Gateway Identity"
            enc_cfg:
                description:
                - "Field enc_cfg"
            uuid:
                description:
                - "uuid of the object"
            nat_traversal:
                description:
                - "Field nat_traversal"
            vrid:
                description:
                - "Field vrid"
            preshare_key_value:
                description:
                - "pre-shared key"
            key_passphrase:
                description:
                - "Private Key Pass Phrase"
            mode:
                description:
                - "'main'= Negotiate Main mode (Default); 'aggressive'= Negotiate Aggressive mode; "
            local_address:
                description:
                - "Field local_address"
            key:
                description:
                - "Private Key"
            preshare_key_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED pre-shared key string)"
            remote_address:
                description:
                - "Field remote_address"
            remote_ca_cert:
                description:
                - "Field remote_ca_cert"
            name:
                description:
                - "IKE-gateway name"
            dh_group:
                description:
                - "'1'= Diffie-Hellman group 1 - 768-bit(Default); '2'= Diffie-Hellman group 2 - 1024-bit; '5'= Diffie-Hellman group 5 - 1536-bit; '14'= Diffie-Hellman group 14 - 2048-bit; '15'= Diffie-Hellman group 15 - 3072-bit; '16'= Diffie-Hellman group 16 - 4096-bit; '18'= Diffie-Hellman group 18 - 8192-bit; '19'= Diffie-Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve; "
            user_tag:
                description:
                - "Customized tag"
            sampling_enable:
                description:
                - "Field sampling_enable"
            dpd:
                description:
                - "Field dpd"
            remote_id:
                description:
                - "Remote Gateway Identity"
            auth_method:
                description:
                - "'preshare-key'= Authenticate the remote gateway using a pre-shared key (Default); 'rsa-signature'= Authenticate the remote gateway using an RSA certificate; 'ecdsa-signature'= Authenticate the remote gateway using an ECDSA certificate; "
    tcp_mss_adjust_disable:
        description:
        - "Disable TCP MSS adjustment in SYN packet"
        required: False
    errordump:
        description:
        - "Field errordump"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    fragment_after_encap:
        description:
        - "Fragment after adding IPsec headers"
        required: False
    ike_stats_global:
        description:
        - "Field ike_stats_global"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    revocation_list:
        description:
        - "Field revocation_list"
        required: False
        suboptions:
            name:
                description:
                - "Revocation name"
            ca:
                description:
                - "Certificate Authority file name"
            user_tag:
                description:
                - "Customized tag"
            ocsp:
                description:
                - "Field ocsp"
            crl:
                description:
                - "Field crl"
            uuid:
                description:
                - "uuid of the object"
    ipsec_error_dump:
        description:
        - "Support record the error ipsec cavium information in dump file"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'passthrough'= passthrough; 'ha-standby-drop'= ha-standby-drop; "
    ipsec_sa_by_gw:
        description:
        - "Field ipsec_sa_by_gw"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    ike_sa_timeout:
        description:
        - "Timeout IKE-SA in connecting state in seconds (default 600s)"
        required: False
    error:
        description:
        - "Field error"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    ipsec_list:
        description:
        - "Field ipsec_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            lifebytes:
                description:
                - "IPsec SA age in megabytes (0 indicates unlimited bytes)"
            bind_tunnel:
                description:
                - "Field bind_tunnel"
            name:
                description:
                - "IPsec name"
            dh_group:
                description:
                - "'0'= Diffie-Hellman group 0 (Default); '1'= Diffie-Hellman group 1 - 768-bits; '2'= Diffie-Hellman group 2 - 1024-bits; '5'= Diffie-Hellman group 5 - 1536-bits; '14'= Diffie-Hellman group 14 - 2048-bits; '15'= Diffie-Hellman group 15 - 3072-bits; '16'= Diffie-Hellman group 16 - 4096-bits; '18'= Diffie-Hellman group 18 - 8192-bits; '19'= Diffie-Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve; "
            proto:
                description:
                - "'esp'= Encapsulating security protocol (Default); "
            up:
                description:
                - "Initiates SA negotiation to bring the IPsec connection up"
            user_tag:
                description:
                - "Customized tag"
            anti_replay_window:
                description:
                - "'0'= Disable Anti-Replay Window Check; '32'= Window size of 32; '64'= Window size of 64; '128'= Window size of 128; '256'= Window size of 256; '512'= Window size of 512; '1024'= Window size of 1024; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            ike_gateway:
                description:
                - "Gateway to use for IPsec SA"
            mode:
                description:
                - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default); "
            sequence_number_disable:
                description:
                - "Do not use incremental sequence number in the ESP header"
            lifetime:
                description:
                - "IPsec SA age in seconds"
            enc_cfg:
                description:
                - "Field enc_cfg"
            traffic_selector:
                description:
                - "Field traffic_selector"
    nat_traversal_flow_affinity:
        description:
        - "Choose IPsec UDP source port based on port of inner flow (only for A10 to A10)"
        required: False
    ocsp:
        description:
        - "Field ocsp"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    stateful_mode:
        description:
        - "VPN module will work in stateful mode and create sessions"
        required: False
    crl:
        description:
        - "Field crl"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["asymmetric_flow_support","crl","default","error","errordump","fragment_after_encap","ike_gateway_list","ike_sa_timeout","ike_stats_global","ipsec_error_dump","ipsec_list","ipsec_sa_by_gw","jumbo_fragment","log","nat_traversal_flow_affinity","ocsp","revocation_list","sampling_enable","stateful_mode","tcp_mss_adjust_disable","uuid",]

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
        jumbo_fragment=dict(type='bool',),
        log=dict(type='dict',uuid=dict(type='str',)),
        asymmetric_flow_support=dict(type='bool',),
        default=dict(type='dict',uuid=dict(type='str',)),
        ike_gateway_list=dict(type='list',ike_version=dict(type='str',choices=['v1','v2']),key_passphrase_encrypted=dict(type='str',),local_cert=dict(type='dict',local_cert_name=dict(type='str',)),lifetime=dict(type='int',),local_id=dict(type='str',),enc_cfg=dict(type='list',priority=dict(type='int',),encryption=dict(type='str',choices=['des','3des','aes-128','aes-192','aes-256','null']),hash=dict(type='str',choices=['md5','sha1','sha256','sha384','sha512'])),uuid=dict(type='str',),nat_traversal=dict(type='bool',),vrid=dict(type='dict',vrid_num=dict(type='int',)),preshare_key_value=dict(type='str',),key_passphrase=dict(type='str',),mode=dict(type='str',choices=['main','aggressive']),local_address=dict(type='dict',local_ip=dict(type='str',),local_ipv6=dict(type='str',)),key=dict(type='str',),preshare_key_encrypted=dict(type='str',),remote_address=dict(type='dict',remote_ip=dict(type='str',),dns=dict(type='str',),remote_ipv6=dict(type='str',)),remote_ca_cert=dict(type='dict',remote_cert_name=dict(type='str',)),name=dict(type='str',required=True,),dh_group=dict(type='str',choices=['1','2','5','14','15','16','18','19','20']),user_tag=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','v2-init-rekey','v2-rsp-rekey','v2-child-sa-rekey','v2-in-invalid','v2-in-invalid-spi','v2-in-init-req','v2-in-init-rsp','v2-out-init-req','v2-out-init-rsp','v2-in-auth-req','v2-in-auth-rsp','v2-out-auth-req','v2-out-auth-rsp','v2-in-create-child-req','v2-in-create-child-rsp','v2-out-create-child-req','v2-out-create-child-rsp','v2-in-info-req','v2-in-info-rsp','v2-out-info-req','v2-out-info-rsp','v1-in-id-prot-req','v1-in-id-prot-rsp','v1-out-id-prot-req','v1-out-id-prot-rsp','v1-in-auth-only-req','v1-in-auth-only-rsp','v1-out-auth-only-req','v1-out-auth-only-rsp','v1-in-aggressive-req','v1-in-aggressive-rsp','v1-out-aggressive-req','v1-out-aggressive-rsp','v1-in-info-v1-req','v1-in-info-v1-rsp','v1-out-info-v1-req','v1-out-info-v1-rsp','v1-in-transaction-req','v1-in-transaction-rsp','v1-out-transaction-req','v1-out-transaction-rsp','v1-in-quick-mode-req','v1-in-quick-mode-rsp','v1-out-quick-mode-req','v1-out-quick-mode-rsp','v1-in-new-group-mode-req','v1-in-new-group-mode-rsp','v1-out-new-group-mode-req','v1-out-new-group-mode-rsp','v1-child-sa-invalid-spi','v2-child-sa-invalid-spi','ike-current-version'])),dpd=dict(type='dict',interval=dict(type='int',),retry=dict(type='int',)),remote_id=dict(type='str',),auth_method=dict(type='str',choices=['preshare-key','rsa-signature','ecdsa-signature'])),
        tcp_mss_adjust_disable=dict(type='bool',),
        errordump=dict(type='dict',uuid=dict(type='str',)),
        fragment_after_encap=dict(type='bool',),
        ike_stats_global=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','v2-init-rekey','v2-rsp-rekey','v2-child-sa-rekey','v2-in-invalid','v2-in-invalid-spi','v2-in-init-req','v2-in-init-rsp','v2-out-init-req','v2-out-init-rsp','v2-in-auth-req','v2-in-auth-rsp','v2-out-auth-req','v2-out-auth-rsp','v2-in-create-child-req','v2-in-create-child-rsp','v2-out-create-child-req','v2-out-create-child-rsp','v2-in-info-req','v2-in-info-rsp','v2-out-info-req','v2-out-info-rsp','v1-in-id-prot-req','v1-in-id-prot-rsp','v1-out-id-prot-req','v1-out-id-prot-rsp','v1-in-auth-only-req','v1-in-auth-only-rsp','v1-out-auth-only-req','v1-out-auth-only-rsp','v1-in-aggressive-req','v1-in-aggressive-rsp','v1-out-aggressive-req','v1-out-aggressive-rsp','v1-in-info-v1-req','v1-in-info-v1-rsp','v1-out-info-v1-req','v1-out-info-v1-rsp','v1-in-transaction-req','v1-in-transaction-rsp','v1-out-transaction-req','v1-out-transaction-rsp','v1-in-quick-mode-req','v1-in-quick-mode-rsp','v1-out-quick-mode-req','v1-out-quick-mode-rsp','v1-in-new-group-mode-req','v1-in-new-group-mode-rsp','v1-out-new-group-mode-req','v1-out-new-group-mode-rsp'])),uuid=dict(type='str',)),
        revocation_list=dict(type='list',name=dict(type='str',required=True,),ca=dict(type='str',),user_tag=dict(type='str',),ocsp=dict(type='dict',ocsp_pri=dict(type='str',),ocsp_sec=dict(type='str',)),crl=dict(type='dict',crl_sec=dict(type='str',),crl_pri=dict(type='str',)),uuid=dict(type='str',)),
        ipsec_error_dump=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','passthrough','ha-standby-drop'])),
        ipsec_sa_by_gw=dict(type='dict',uuid=dict(type='str',)),
        ike_sa_timeout=dict(type='int',),
        error=dict(type='dict',uuid=dict(type='str',)),
        ipsec_list=dict(type='list',uuid=dict(type='str',),lifebytes=dict(type='int',),bind_tunnel=dict(type='dict',tunnel=dict(type='int',),next_hop=dict(type='str',),uuid=dict(type='str',),next_hop_v6=dict(type='str',)),name=dict(type='str',required=True,),dh_group=dict(type='str',choices=['0','1','2','5','14','15','16','18','19','20']),proto=dict(type='str',choices=['esp']),up=dict(type='bool',),user_tag=dict(type='str',),anti_replay_window=dict(type='str',choices=['0','32','64','128','256','512','1024']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','packets-encrypted','packets-decrypted','anti-replay-num','rekey-num','packets-err-inactive','packets-err-encryption','packets-err-pad-check','packets-err-pkt-sanity','packets-err-icv-check','packets-err-lifetime-lifebytes','bytes-encrypted','bytes-decrypted','prefrag-success','prefrag-error','cavium-bytes-encrypted','cavium-bytes-decrypted','cavium-packets-encrypted','cavium-packets-decrypted','tunnel-intf-down','pkt-fail-prep-to-send','no-next-hop','invalid-tunnel-id','no-tunnel-found','pkt-fail-to-send','frag-after-encap-frag-packets','frag-received','sequence-num','sequence-num-rollover','packets-err-nh-check'])),ike_gateway=dict(type='str',),mode=dict(type='str',choices=['tunnel']),sequence_number_disable=dict(type='bool',),lifetime=dict(type='int',),enc_cfg=dict(type='list',priority=dict(type='int',),encryption=dict(type='str',choices=['des','3des','aes-128','aes-192','aes-256','aes-gcm-128','aes-gcm-192','aes-gcm-256','null']),gcm_priority=dict(type='int',),hash=dict(type='str',choices=['md5','sha1','sha256','sha384','sha512','null'])),traffic_selector=dict(type='dict',ipv4=dict(type='dict',remote=dict(type='str',),local_port=dict(type='int',),remote_port=dict(type='int',),local_netmask=dict(type='str',),remote_netmask=dict(type='str',),protocol=dict(type='int',),local=dict(type='str',)),ipv6=dict(type='dict',local_portv6=dict(type='int',),protocolv6=dict(type='int',),localv6=dict(type='str',),remotev6=dict(type='str',),remote_portv6=dict(type='int',)))),
        nat_traversal_flow_affinity=dict(type='bool',),
        ocsp=dict(type='dict',uuid=dict(type='str',)),
        stateful_mode=dict(type='bool',),
        crl=dict(type='dict',uuid=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["vpn"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["vpn"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["vpn"][k] = v
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
    payload = build_json("vpn", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
        result = absent(module, result, existing_config)
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