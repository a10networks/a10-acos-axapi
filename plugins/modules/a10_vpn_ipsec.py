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
        - "IPsec name"
        type: str
        required: True
    mode:
        description:
        - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default);"
        type: str
        required: False
    dscp:
        description:
        - "'default'= Default dscp (000000); 'af11'= AF11 (001010); 'af12'= AF12 (001100);
          'af13'= AF13 (001110); 'af21'= AF21 (010010); 'af22'= AF22 (010100); 'af23'=
          AF23 (010110); 'af31'= AF31 (011010); 'af32'= AF32 (011100); 'af33'= AF33
          (011110); 'af41'= AF41 (100010); 'af42'= AF42 (100100); 'af43'= AF43 (100110);
          'cs1'= CS1 (001000); 'cs2'= CS2 (010000); 'cs3'= CS3 (011000); 'cs4'= CS4
          (100000); 'cs5'= CS5 (101000); 'cs6'= CS6 (110000); 'cs7'= CS7 (111000); 'ef'=
          EF (101110); '0'= 000000; '1'= 000001; '2'= 000010; '3'= 000011; '4'= 000100;
          '5'= 000101; '6'= 000110; '7'= 000111; '8'= 001000; '9'= 001001; '10'= 001010;
          '11'= 001011; '12'= 001100; '13'= 001101; '14'= 001110; '15'= 001111; '16'=
          010000; '17'= 010001; '18'= 010010; '19'= 010011; '20'= 010100; '21'= 010101;
          '22'= 010110; '23'= 010111; '24'= 011000; '25'= 011001; '26'= 011010; '27'=
          011011; '28'= 011100; '29'= 011101; '30'= 011110; '31'= 011111; '32'= 100000;
          '33'= 100001; '34'= 100010; '35'= 100011; '36'= 100100; '37'= 100101; '38'=
          100110; '39'= 100111; '40'= 101000; '41'= 101001; '42'= 101010; '43'= 101011;
          '44'= 101100; '45'= 101101; '46'= 101110; '47'= 101111; '48'= 110000; '49'=
          110001; '50'= 110010; '51'= 110011; '52'= 110100; '53'= 110101; '54'= 110110;
          '55'= 110111; '56'= 111000; '57'= 111001; '58'= 111010; '59'= 111011; '60'=
          111100; '61'= 111101; '62'= 111110; '63'= 111111;"
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
          size of 512; '1024'= Window size of 1024; '2048'= Window size of 2048; '3072'=
          Window size of 3072; '4096'= Window size of 4096; '8192'= Window size of 8192;"
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
    enforce_traffic_selector:
        description:
        - "Enforce Traffic Selector"
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
          CAVIUM Decrypted Packets; 'qat-bytes-encrypted'= QAT Encrypted Bytes; 'qat-
          bytes-decrypted'= QAT Decrypted Bytes; 'qat-packets-encrypted'= QAT Encrypted
          Packets; 'qat-packets-decrypted'= QAT Decrypted Packets; 'tunnel-intf-down'=
          Packet dropped= Tunnel Interface Down; 'pkt-fail-prep-to-send'= Packet dropped=
          Failed in prepare to send; 'no-next-hop'= Packet dropped= No next hop;
          'invalid-tunnel-id'= Packet dropped= Invalid tunnel ID; 'no-tunnel-found'=
          Packet dropped= No tunnel found; 'pkt-fail-to-send'= Packet dropped= Failed to
          send; 'frag-after-encap-frag-packets'= Frag-after-encap Fragment Generated;
          'frag-received'= Fragment Received; 'sequence-num'= Sequence Number; 'sequence-
          num-rollover'= Sequence Number Rollover; 'packets-err-nh-check'= Next Header
          Check Error;"
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
    ipsec_gateway:
        description:
        - "Field ipsec_gateway"
        type: dict
        required: False
        suboptions:
            ike_gateway:
                description:
                - "Gateway to use for IPsec SA"
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
            remote_ts_filter:
                description:
                - "Field remote_ts_filter"
                type: str
            remote_ts_v6_filter:
                description:
                - "Field remote_ts_v6_filter"
                type: str
            in_spi_filter:
                description:
                - "Field in_spi_filter"
                type: str
            out_spi_filter:
                description:
                - "Field out_spi_filter"
                type: str
            SA_List:
                description:
                - "Field SA_List"
                type: list
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
            qat_bytes_encrypted:
                description:
                - "QAT Encrypted Bytes"
                type: str
            qat_bytes_decrypted:
                description:
                - "QAT Decrypted Bytes"
                type: str
            qat_packets_encrypted:
                description:
                - "QAT Encrypted Packets"
                type: str
            qat_packets_decrypted:
                description:
                - "QAT Decrypted Packets"
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
AVAILABLE_PROPERTIES = ["anti_replay_window", "bind_tunnel", "dh_group", "dscp", "enc_cfg", "enforce_traffic_selector", "ipsec_gateway", "lifebytes", "lifetime", "mode", "name", "oper", "proto", "sampling_enable", "sequence_number_disable", "stats", "traffic_selector", "up", "user_tag", "uuid", ]


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
        'mode': {
            'type': 'str',
            'choices': ['tunnel']
            },
        'dscp': {
            'type':
            'str',
            'choices': [
                'default', 'af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29',
                '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63'
                ]
            },
        'proto': {
            'type': 'str',
            'choices': ['esp']
            },
        'dh_group': {
            'type': 'str',
            'choices': ['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']
            },
        'enc_cfg': {
            'type': 'list',
            'encryption': {
                'type': 'str',
                'choices': ['des', '3des', 'aes-128', 'aes-192', 'aes-256', 'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null']
                },
            'hash': {
                'type': 'str',
                'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'null']
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
            'choices': ['0', '32', '64', '128', '256', '512', '1024', '2048', '3072', '4096', '8192']
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
                'remote_ipv4_assigned': {
                    'type': 'bool',
                    },
                'remote_ip': {
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
                'remote_ipv6_assigned': {
                    'type': 'bool',
                    },
                'remote_ipv6': {
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
        'enforce_traffic_selector': {
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
                'type':
                'str',
                'choices': [
                    'all', 'packets-encrypted', 'packets-decrypted', 'anti-replay-num', 'rekey-num', 'packets-err-inactive', 'packets-err-encryption', 'packets-err-pad-check', 'packets-err-pkt-sanity', 'packets-err-icv-check', 'packets-err-lifetime-lifebytes', 'bytes-encrypted', 'bytes-decrypted', 'prefrag-success', 'prefrag-error',
                    'cavium-bytes-encrypted', 'cavium-bytes-decrypted', 'cavium-packets-encrypted', 'cavium-packets-decrypted', 'qat-bytes-encrypted', 'qat-bytes-decrypted', 'qat-packets-encrypted', 'qat-packets-decrypted', 'tunnel-intf-down', 'pkt-fail-prep-to-send', 'no-next-hop', 'invalid-tunnel-id', 'no-tunnel-found', 'pkt-fail-to-send',
                    'frag-after-encap-frag-packets', 'frag-received', 'sequence-num', 'sequence-num-rollover', 'packets-err-nh-check'
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
        'ipsec_gateway': {
            'type': 'dict',
            'ike_gateway': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'remote_ts_filter': {
                'type': 'str',
                },
            'remote_ts_v6_filter': {
                'type': 'str',
                },
            'in_spi_filter': {
                'type': 'str',
                },
            'out_spi_filter': {
                'type': 'str',
                },
            'SA_List': {
                'type': 'list',
                'Status': {
                    'type': 'str',
                    },
                'SA_Index': {
                    'type': 'int',
                    },
                'TS_Proto': {
                    'type': 'int',
                    },
                'Local_IP': {
                    'type': 'str',
                    },
                'Local_Port': {
                    'type': 'int',
                    },
                'Peer_IP': {
                    'type': 'str',
                    },
                'Peer_Port': {
                    'type': 'int',
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
                'Lifetime': {
                    'type': 'int',
                    },
                'Lifebytes': {
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
                'packets_encrypted': {
                    'type': 'int',
                    },
                'packets_decrypted': {
                    'type': 'int',
                    },
                'anti_replay_num': {
                    'type': 'int',
                    },
                'rekey_num': {
                    'type': 'int',
                    },
                'packets_err_inactive': {
                    'type': 'int',
                    },
                'packets_err_encryption': {
                    'type': 'int',
                    },
                'packets_err_pad_check': {
                    'type': 'int',
                    },
                'packets_err_pkt_sanity': {
                    'type': 'int',
                    },
                'packets_err_icv_check': {
                    'type': 'int',
                    },
                'packets_err_lifetime_lifebytes': {
                    'type': 'int',
                    },
                'bytes_encrypted': {
                    'type': 'int',
                    },
                'bytes_decrypted': {
                    'type': 'int',
                    },
                'prefrag_success': {
                    'type': 'int',
                    },
                'prefrag_error': {
                    'type': 'int',
                    },
                'cavium_bytes_encrypted': {
                    'type': 'int',
                    },
                'cavium_bytes_decrypted': {
                    'type': 'int',
                    },
                'cavium_packets_encrypted': {
                    'type': 'int',
                    },
                'cavium_packets_decrypted': {
                    'type': 'int',
                    },
                'qat_bytes_encrypted': {
                    'type': 'int',
                    },
                'qat_bytes_decrypted': {
                    'type': 'int',
                    },
                'qat_packets_encrypted': {
                    'type': 'int',
                    },
                'qat_packets_decrypted': {
                    'type': 'int',
                    },
                'tunnel_intf_down': {
                    'type': 'int',
                    },
                'pkt_fail_prep_to_send': {
                    'type': 'int',
                    },
                'no_next_hop': {
                    'type': 'int',
                    },
                'invalid_tunnel_id': {
                    'type': 'int',
                    },
                'no_tunnel_found': {
                    'type': 'int',
                    },
                'pkt_fail_to_send': {
                    'type': 'int',
                    },
                'frag_after_encap_frag_packets': {
                    'type': 'int',
                    },
                'frag_received': {
                    'type': 'int',
                    },
                'sequence_num': {
                    'type': 'int',
                    },
                'sequence_num_rollover': {
                    'type': 'int',
                    },
                'packets_err_nh_check': {
                    'type': 'int',
                    },
                'enforce_ts_encap_drop': {
                    'type': 'int',
                    },
                'enforce_ts_decap_drop': {
                    'type': 'int',
                    }
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
            'qat_bytes_encrypted': {
                'type': 'str',
                },
            'qat_bytes_decrypted': {
                'type': 'str',
                },
            'qat_packets_encrypted': {
                'type': 'str',
                },
            'qat_packets_decrypted': {
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
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/ipsec"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ipsec"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ipsec"].get(k) != v:
            change_results["changed"] = True
            config_changes["ipsec"][k] = v

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
    payload = utils.build_json("ipsec", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["ipsec"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ipsec-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["ipsec"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ipsec"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
