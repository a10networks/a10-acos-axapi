#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vpn_ipsec
description:
    - IPsec settings
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
        - "IPsec name"
        type: str
        required: True
    ike_gateway:
        description:
        - "Gateway to use for IPsec SA"
        type: str
        required: False
    mode:
        description:
        - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default);"
        type: str
        required: False
    proto:
        description:
        - "'esp'= Encapsulating security protocol (Default);"
        type: str
        required: False
    dh_group:
        description:
        - "'0'= Diffie-Hellman group 0 (Default); '1'= Diffie-Hellman group 1 - 768-bits;
          '2'= Diffie-Hellman group 2 - 1024-bits; '5'= Diffie-Hellman group 5 -
          1536-bits; '14'= Diffie-Hellman group 14 - 2048-bits; '15'= Diffie-Hellman
          group 15 - 3072-bits; '16'= Diffie-Hellman group 16 - 4096-bits; '18'= Diffie-
          Hellman group 18 - 8192-bits; '19'= Diffie-Hellman group 19 - 256-bit Elliptic
          Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve;"
        type: str
        required: False
    enc_cfg:
        description:
        - "Field enc_cfg"
        type: list
        required: False
        suboptions:
            encryption:
                description:
                - "'des'= Data Encryption Standard algorithm; '3des'= Triple Data Encryption
          Standard algorithm; 'aes-128'= Advanced Encryption Standard algorithm CBC
          Mode(key size= 128 bits); 'aes-192'= Advanced Encryption Standard algorithm CBC
          Mode(key size= 192 bits); 'aes-256'= Advanced Encryption Standard algorithm CBC
          Mode(key size= 256 bits); 'aes-gcm-128'= Advanced Encryption Standard algorithm
          Galois/Counter Mode(key size= 128 bits, ICV size= 16 bytes); 'aes-gcm-192'=
          Advanced Encryption Standard algorithm Galois/Counter Mode(key size= 192 bits,
          ICV size= 16 bytes); 'aes-gcm-256'= Advanced Encryption Standard algorithm
          Galois/Counter Mode(key size= 256 bits, ICV size= 16 bytes); 'null'= No
          encryption algorithm;"
                type: str
            hash:
                description:
                - "'md5'= MD5 Dessage-Digest Algorithm; 'sha1'= Secure Hash Algorithm 1; 'sha256'=
          Secure Hash Algorithm 256; 'sha384'= Secure Hash Algorithm 384; 'sha512'=
          Secure Hash Algorithm 512; 'null'= No hash algorithm;"
                type: str
            priority:
                description:
                - "Prioritizes (1-10) security protocol, least value has highest priority"
                type: int
            gcm_priority:
                description:
                - "Prioritizes (1-10) security protocol, least value has highest priority"
                type: int
    lifetime:
        description:
        - "IPsec SA age in seconds"
        type: int
        required: False
    lifebytes:
        description:
        - "IPsec SA age in megabytes (0 indicates unlimited bytes)"
        type: int
        required: False
    anti_replay_window:
        description:
        - "'0'= Disable Anti-Replay Window Check; '32'= Window size of 32; '64'= Window
          size of 64; '128'= Window size of 128; '256'= Window size of 256; '512'= Window
          size of 512; '1024'= Window size of 1024;"
        type: str
        required: False
    up:
        description:
        - "Initiates SA negotiation to bring the IPsec connection up"
        type: bool
        required: False
    sequence_number_disable:
        description:
        - "Do not use incremental sequence number in the ESP header"
        type: bool
        required: False
    traffic_selector:
        description:
        - "Field traffic_selector"
        type: dict
        required: False
        suboptions:
            ipv4:
                description:
                - "Field ipv4"
                type: dict
            ipv6:
                description:
                - "Field ipv6"
                type: dict
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
                - "'all'= all; 'packets-encrypted'= Encrypted Packets; 'packets-decrypted'=
          Decrypted Packets; 'anti-replay-num'= Anti-Replay Failure; 'rekey-num'= Rekey
          Times; 'packets-err-inactive'= Inactive Error; 'packets-err-encryption'=
          Encryption Error; 'packets-err-pad-check'= Pad Check Error; 'packets-err-pkt-
          sanity'= Packets Sanity Error; 'packets-err-icv-check'= ICV Check Error;
          'packets-err-lifetime-lifebytes'= Lifetime Lifebytes Error; 'bytes-encrypted'=
          Encrypted Bytes; 'bytes-decrypted'= Decrypted Bytes; 'prefrag-success'= Pre-
          frag Success; 'prefrag-error'= Pre-frag Error; 'cavium-bytes-encrypted'= CAVIUM
          Encrypted Bytes; 'cavium-bytes-decrypted'= CAVIUM Decrypted Bytes; 'cavium-
          packets-encrypted'= CAVIUM Encrypted Packets; 'cavium-packets-decrypted'=
          CAVIUM Decrypted Packets; 'tunnel-intf-down'= Packet dropped= Tunnel Interface
          Down; 'pkt-fail-prep-to-send'= Packet dropped= Failed in prepare to send; 'no-
          next-hop'= Packet dropped= No next hop; 'invalid-tunnel-id'= Packet dropped=
          Invalid tunnel ID; 'no-tunnel-found'= Packet dropped= No tunnel found; 'pkt-
          fail-to-send'= Packet dropped= Failed to send; 'frag-after-encap-frag-packets'=
          Frag-after-encap Fragment Generated; 'frag-received'= Fragment Received;
          'sequence-num'= Sequence Number; 'sequence-num-rollover'= Sequence Number
          Rollover; 'packets-err-nh-check'= Next Header Check Error;"
                type: str
    bind_tunnel:
        description:
        - "Field bind_tunnel"
        type: dict
        required: False
        suboptions:
            tunnel:
                description:
                - "Tunnel interface index"
                type: int
            next_hop:
                description:
                - "IPsec Next Hop IP Address"
                type: str
            next_hop_v6:
                description:
                - "IPsec Next Hop IPv6 Address"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            Status:
                description:
                - "Field Status"
                type: str
            SA_Index:
                description:
                - "Field SA_Index"
                type: int
            Local_IP:
                description:
                - "Field Local_IP"
                type: str
            Peer_IP:
                description:
                - "Field Peer_IP"
                type: str
            Local_SPI:
                description:
                - "Field Local_SPI"
                type: str
            Remote_SPI:
                description:
                - "Field Remote_SPI"
                type: str
            Protocol:
                description:
                - "Field Protocol"
                type: str
            Mode:
                description:
                - "Field Mode"
                type: str
            Encryption_Algorithm:
                description:
                - "Field Encryption_Algorithm"
                type: str
            Hash_Algorithm:
                description:
                - "Field Hash_Algorithm"
                type: str
            DH_Group:
                description:
                - "Field DH_Group"
                type: int
            NAT_Traversal:
                description:
                - "Field NAT_Traversal"
                type: int
            Anti_Replay:
                description:
                - "Field Anti_Replay"
                type: str
            Lifetime:
                description:
                - "Field Lifetime"
                type: int
            Lifebytes:
                description:
                - "Field Lifebytes"
                type: str
            name:
                description:
                - "IPsec name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_encrypted:
                description:
                - "Encrypted Packets"
                type: str
            packets_decrypted:
                description:
                - "Decrypted Packets"
                type: str
            anti_replay_num:
                description:
                - "Anti-Replay Failure"
                type: str
            rekey_num:
                description:
                - "Rekey Times"
                type: str
            packets_err_inactive:
                description:
                - "Inactive Error"
                type: str
            packets_err_encryption:
                description:
                - "Encryption Error"
                type: str
            packets_err_pad_check:
                description:
                - "Pad Check Error"
                type: str
            packets_err_pkt_sanity:
                description:
                - "Packets Sanity Error"
                type: str
            packets_err_icv_check:
                description:
                - "ICV Check Error"
                type: str
            packets_err_lifetime_lifebytes:
                description:
                - "Lifetime Lifebytes Error"
                type: str
            bytes_encrypted:
                description:
                - "Encrypted Bytes"
                type: str
            bytes_decrypted:
                description:
                - "Decrypted Bytes"
                type: str
            prefrag_success:
                description:
                - "Pre-frag Success"
                type: str
            prefrag_error:
                description:
                - "Pre-frag Error"
                type: str
            cavium_bytes_encrypted:
                description:
                - "CAVIUM Encrypted Bytes"
                type: str
            cavium_bytes_decrypted:
                description:
                - "CAVIUM Decrypted Bytes"
                type: str
            cavium_packets_encrypted:
                description:
                - "CAVIUM Encrypted Packets"
                type: str
            cavium_packets_decrypted:
                description:
                - "CAVIUM Decrypted Packets"
                type: str
            tunnel_intf_down:
                description:
                - "Packet dropped= Tunnel Interface Down"
                type: str
            pkt_fail_prep_to_send:
                description:
                - "Packet dropped= Failed in prepare to send"
                type: str
            no_next_hop:
                description:
                - "Packet dropped= No next hop"
                type: str
            invalid_tunnel_id:
                description:
                - "Packet dropped= Invalid tunnel ID"
                type: str
            no_tunnel_found:
                description:
                - "Packet dropped= No tunnel found"
                type: str
            pkt_fail_to_send:
                description:
                - "Packet dropped= Failed to send"
                type: str
            frag_after_encap_frag_packets:
                description:
                - "Frag-after-encap Fragment Generated"
                type: str
            frag_received:
                description:
                - "Fragment Received"
                type: str
            sequence_num:
                description:
                - "Sequence Number"
                type: str
            sequence_num_rollover:
                description:
                - "Sequence Number Rollover"
                type: str
            packets_err_nh_check:
                description:
                - "Next Header Check Error"
                type: str
            name:
                description:
                - "IPsec name"
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
    "anti_replay_window",
    "bind_tunnel",
    "dh_group",
    "enc_cfg",
    "ike_gateway",
    "lifebytes",
    "lifetime",
    "mode",
    "name",
    "oper",
    "proto",
    "sampling_enable",
    "sequence_number_disable",
    "stats",
    "traffic_selector",
    "up",
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
        'ike_gateway': {
            'type': 'str',
        },
        'mode': {
            'type': 'str',
            'choices': ['tunnel']
        },
        'proto': {
            'type': 'str',
            'choices': ['esp']
        },
        'dh_group': {
            'type': 'str',
            'choices':
            ['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']
        },
        'enc_cfg': {
            'type': 'list',
            'encryption': {
                'type':
                'str',
                'choices': [
                    'des', '3des', 'aes-128', 'aes-192', 'aes-256',
                    'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null'
                ]
            },
            'hash': {
                'type': 'str',
                'choices':
                ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'null']
            },
            'priority': {
                'type': 'int',
            },
            'gcm_priority': {
                'type': 'int',
            }
        },
        'lifetime': {
            'type': 'int',
        },
        'lifebytes': {
            'type': 'int',
        },
        'anti_replay_window': {
            'type': 'str',
            'choices': ['0', '32', '64', '128', '256', '512', '1024']
        },
        'up': {
            'type': 'bool',
        },
        'sequence_number_disable': {
            'type': 'bool',
        },
        'traffic_selector': {
            'type': 'dict',
            'ipv4': {
                'type': 'dict',
                'local': {
                    'type': 'str',
                },
                'local_netmask': {
                    'type': 'str',
                },
                'local_port': {
                    'type': 'int',
                },
                'remote': {
                    'type': 'str',
                },
                'remote_netmask': {
                    'type': 'str',
                },
                'remote_port': {
                    'type': 'int',
                },
                'protocol': {
                    'type': 'int',
                }
            },
            'ipv6': {
                'type': 'dict',
                'localv6': {
                    'type': 'str',
                },
                'local_portv6': {
                    'type': 'int',
                },
                'remotev6': {
                    'type': 'str',
                },
                'remote_portv6': {
                    'type': 'int',
                },
                'protocolv6': {
                    'type': 'int',
                }
            }
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
                    'all', 'packets-encrypted', 'packets-decrypted',
                    'anti-replay-num', 'rekey-num', 'packets-err-inactive',
                    'packets-err-encryption', 'packets-err-pad-check',
                    'packets-err-pkt-sanity', 'packets-err-icv-check',
                    'packets-err-lifetime-lifebytes', 'bytes-encrypted',
                    'bytes-decrypted', 'prefrag-success', 'prefrag-error',
                    'cavium-bytes-encrypted', 'cavium-bytes-decrypted',
                    'cavium-packets-encrypted', 'cavium-packets-decrypted',
                    'tunnel-intf-down', 'pkt-fail-prep-to-send', 'no-next-hop',
                    'invalid-tunnel-id', 'no-tunnel-found', 'pkt-fail-to-send',
                    'frag-after-encap-frag-packets', 'frag-received',
                    'sequence-num', 'sequence-num-rollover',
                    'packets-err-nh-check'
                ]
            }
        },
        'bind_tunnel': {
            'type': 'dict',
            'tunnel': {
                'type': 'int',
            },
            'next_hop': {
                'type': 'str',
            },
            'next_hop_v6': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'Status': {
                'type': 'str',
            },
            'SA_Index': {
                'type': 'int',
            },
            'Local_IP': {
                'type': 'str',
            },
            'Peer_IP': {
                'type': 'str',
            },
            'Local_SPI': {
                'type': 'str',
            },
            'Remote_SPI': {
                'type': 'str',
            },
            'Protocol': {
                'type': 'str',
            },
            'Mode': {
                'type': 'str',
            },
            'Encryption_Algorithm': {
                'type': 'str',
            },
            'Hash_Algorithm': {
                'type': 'str',
            },
            'DH_Group': {
                'type': 'int',
            },
            'NAT_Traversal': {
                'type': 'int',
            },
            'Anti_Replay': {
                'type': 'str',
            },
            'Lifetime': {
                'type': 'int',
            },
            'Lifebytes': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'packets_encrypted': {
                'type': 'str',
            },
            'packets_decrypted': {
                'type': 'str',
            },
            'anti_replay_num': {
                'type': 'str',
            },
            'rekey_num': {
                'type': 'str',
            },
            'packets_err_inactive': {
                'type': 'str',
            },
            'packets_err_encryption': {
                'type': 'str',
            },
            'packets_err_pad_check': {
                'type': 'str',
            },
            'packets_err_pkt_sanity': {
                'type': 'str',
            },
            'packets_err_icv_check': {
                'type': 'str',
            },
            'packets_err_lifetime_lifebytes': {
                'type': 'str',
            },
            'bytes_encrypted': {
                'type': 'str',
            },
            'bytes_decrypted': {
                'type': 'str',
            },
            'prefrag_success': {
                'type': 'str',
            },
            'prefrag_error': {
                'type': 'str',
            },
            'cavium_bytes_encrypted': {
                'type': 'str',
            },
            'cavium_bytes_decrypted': {
                'type': 'str',
            },
            'cavium_packets_encrypted': {
                'type': 'str',
            },
            'cavium_packets_decrypted': {
                'type': 'str',
            },
            'tunnel_intf_down': {
                'type': 'str',
            },
            'pkt_fail_prep_to_send': {
                'type': 'str',
            },
            'no_next_hop': {
                'type': 'str',
            },
            'invalid_tunnel_id': {
                'type': 'str',
            },
            'no_tunnel_found': {
                'type': 'str',
            },
            'pkt_fail_to_send': {
                'type': 'str',
            },
            'frag_after_encap_frag_packets': {
                'type': 'str',
            },
            'frag_received': {
                'type': 'str',
            },
            'sequence_num': {
                'type': 'str',
            },
            'sequence_num_rollover': {
                'type': 'str',
            },
            'packets_err_nh_check': {
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
    url_base = "/axapi/v3/vpn/ipsec/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/vpn/ipsec/{name}"

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
        for k, v in payload["ipsec"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ipsec"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ipsec"][k] = v
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
    payload = build_json("ipsec", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
