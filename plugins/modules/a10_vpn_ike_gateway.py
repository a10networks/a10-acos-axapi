#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vpn_ike_gateway
description:
    - IKE-gateway settings
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
        - "IKE-gateway name"
        type: str
        required: True
    ike_version:
        description:
        - "'v1'= IKEv1 key exchange; 'v2'= IKEv2 key exchange;"
        type: str
        required: False
    mode:
        description:
        - "'main'= Negotiate Main mode (Default); 'aggressive'= Negotiate Aggressive mode;"
        type: str
        required: False
    auth_method:
        description:
        - "'preshare-key'= Authenticate the remote gateway using a pre-shared key
          (Default); 'rsa-signature'= Authenticate the remote gateway using an RSA
          certificate; 'ecdsa-signature'= Authenticate the remote gateway using an ECDSA
          certificate; 'eap-radius'= Authenticate the remote gateway using an EAP Radius
          server; 'eap-tls'= Authenticate the remote gateway using EAP TLS;"
        type: str
        required: False
    preshare_key_value:
        description:
        - "pre-shared key"
        type: str
        required: False
    preshare_key_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED pre-shared key string)"
        type: str
        required: False
    hash:
        description:
        - "'sha256'= Secure Hash Algorithm 256; 'sha384'= Secure Hash Algorithm 384;
          'sha512'= Secure Hash Algorithm 512;"
        type: str
        required: False
    interface_management:
        description:
        - "only handle traffic on management interface, share partition only"
        type: bool
        required: False
    key:
        description:
        - "Private Key"
        type: str
        required: False
    key_passphrase:
        description:
        - "Private Key Pass Phrase"
        type: str
        required: False
    key_passphrase_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED key string)"
        type: str
        required: False
    vrid:
        description:
        - "Field vrid"
        type: dict
        required: False
        suboptions:
            default:
                description:
                - "Default VRRP-A vrid"
                type: bool
            vrid_num:
                description:
                - "Specify ha VRRP-A vrid"
                type: int
    local_cert:
        description:
        - "Field local_cert"
        type: dict
        required: False
        suboptions:
            local_cert_name:
                description:
                - "Certificate File Name"
                type: str
    remote_ca_cert:
        description:
        - "Field remote_ca_cert"
        type: dict
        required: False
        suboptions:
            remote_cert_name:
                description:
                - "Remote CA certificate DN (C=, ST=, L=, O=, CN=) without emailAddress"
                type: str
    local_id:
        description:
        - "Local Gateway Identity"
        type: str
        required: False
    remote_id:
        description:
        - "Remote Gateway Identity"
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
          Galois/Counter Mode(key size= 128 bits, ICV size= 16 bytes), only for IKEv2;
          'aes-gcm-192'= Advanced Encryption Standard algorithm Galois/Counter Mode(key
          size= 192 bits, ICV size= 16 bytes), only for IKEv2; 'aes-gcm-256'= Advanced
          Encryption Standard algorithm Galois/Counter Mode(key size= 256 bits, ICV size=
          16 bytes), only for IKEv2; 'null'= No encryption algorithm, only for IKEv2;"
                type: str
            hash:
                description:
                - "'md5'= MD5 Dessage-Digest Algorithm; 'sha1'= Secure Hash Algorithm 1; 'sha256'=
          Secure Hash Algorithm 256; 'sha384'= Secure Hash Algorithm 384; 'sha512'=
          Secure Hash Algorithm 512;"
                type: str
            prf:
                description:
                - "'md5'= MD5 Dessage-Digest Algorithm; 'sha1'= Secure Hash Algorithm 1; 'sha256'=
          Secure Hash Algorithm 256; 'sha384'= Secure Hash Algorithm 384; 'sha512'=
          Secure Hash Algorithm 512;"
                type: str
            priority:
                description:
                - "Prioritizes (1-10) security protocol, least value has highest priority"
                type: int
            gcm_priority:
                description:
                - "Prioritizes (1-10) security protocol, least value has highest priority"
                type: int
    dh_group:
        description:
        - "'1'= Diffie-Hellman group 1 - 768-bit(Default); '2'= Diffie-Hellman group 2 -
          1024-bit; '5'= Diffie-Hellman group 5 - 1536-bit; '14'= Diffie-Hellman group 14
          - 2048-bit; '15'= Diffie-Hellman group 15 - 3072-bit; '16'= Diffie-Hellman
          group 16 - 4096-bit; '18'= Diffie-Hellman group 18 - 8192-bit; '19'= Diffie-
          Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 -
          384-bit Elliptic Curve;"
        type: str
        required: False
    local_address:
        description:
        - "Field local_address"
        type: dict
        required: False
        suboptions:
            local_ip:
                description:
                - "Ipv4 address"
                type: str
            local_ipv6:
                description:
                - "Ipv6 address"
                type: str
    remote_address:
        description:
        - "Field remote_address"
        type: dict
        required: False
        suboptions:
            remote_ip:
                description:
                - "Ipv4 address"
                type: str
            dns:
                description:
                - "Remote IP based on Domain name"
                type: str
            remote_ipv6:
                description:
                - "Ipv6 address"
                type: str
    lifetime:
        description:
        - "IKE SA age in seconds"
        type: int
        required: False
    fragment_size:
        description:
        - "Enable IKE message fragment and set fragment size"
        type: int
        required: False
    nat_traversal:
        description:
        - "Field nat_traversal"
        type: bool
        required: False
    dpd:
        description:
        - "Field dpd"
        type: dict
        required: False
        suboptions:
            interval:
                description:
                - "Interval time in seconds"
                type: int
            retry:
                description:
                - "Retry times"
                type: int
    disable_rekey:
        description:
        - "Disable initiating rekey"
        type: bool
        required: False
    configuration_payload:
        description:
        - "'dhcp'= Enable DHCP configuration-payload; 'radius'= Enable RADIUS
          configuration-payload;"
        type: str
        required: False
    dhcp_server:
        description:
        - "Field dhcp_server"
        type: dict
        required: False
        suboptions:
            pri:
                description:
                - "Field pri"
                type: dict
            sec:
                description:
                - "Field sec"
                type: dict
    radius_server:
        description:
        - "Field radius_server"
        type: dict
        required: False
        suboptions:
            radius_pri:
                description:
                - "Primary RADIUS Authentication Server"
                type: str
            radius_sec:
                description:
                - "Secondary RADIUS Authentication Server"
                type: str
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
                - "'all'= all; 'v2-init-rekey'= Initiate Rekey; 'v2-rsp-rekey'= Respond Rekey;
          'v2-child-sa-rekey'= Child SA Rekey; 'v2-in-invalid'= Incoming Invalid; 'v2-in-
          invalid-spi'= Incoming Invalid SPI; 'v2-in-init-req'= Incoming Init Request;
          'v2-in-init-rsp'= Incoming Init Response; 'v2-out-init-req'= Outgoing Init
          Request; 'v2-out-init-rsp'= Outgoing Init Response; 'v2-in-auth-req'= Incoming
          Auth Request; 'v2-in-auth-rsp'= Incoming Auth Response; 'v2-out-auth-req'=
          Outgoing Auth Request; 'v2-out-auth-rsp'= Outgoing Auth Response; 'v2-in-
          create-child-req'= Incoming Create Child Request; 'v2-in-create-child-rsp'=
          Incoming Create Child Response; 'v2-out-create-child-req'= Outgoing Create
          Child Request; 'v2-out-create-child-rsp'= Outgoing Create Child Response;
          'v2-in-info-req'= Incoming Info Request; 'v2-in-info-rsp'= Incoming Info
          Response; 'v2-out-info-req'= Outgoing Info Request; 'v2-out-info-rsp'= Outgoing
          Info Response; 'v1-in-id-prot-req'= Incoming ID Protection Request; 'v1-in-id-
          prot-rsp'= Incoming ID Protection Response; 'v1-out-id-prot-req'= Outgoing ID
          Protection Request; 'v1-out-id-prot-rsp'= Outgoing ID Protection Response;
          'v1-in-auth-only-req'= Incoming Auth Only Request; 'v1-in-auth-only-rsp'=
          Incoming Auth Only Response; 'v1-out-auth-only-req'= Outgoing Auth Only
          Request; 'v1-out-auth-only-rsp'= Outgoing Auth Only Response; 'v1-in-
          aggressive-req'= Incoming Aggressive Request; 'v1-in-aggressive-rsp'= Incoming
          Aggressive Response; 'v1-out-aggressive-req'= Outgoing Aggressive Request;
          'v1-out-aggressive-rsp'= Outgoing Aggressive Response; 'v1-in-info-v1-req'=
          Incoming Info Request; 'v1-in-info-v1-rsp'= Incoming Info Response; 'v1-out-
          info-v1-req'= Outgoing Info Request; 'v1-out-info-v1-rsp'= Outgoing Info
          Response; 'v1-in-transaction-req'= Incoming Transaction Request; 'v1-in-
          transaction-rsp'= Incoming Transaction Response; 'v1-out-transaction-req'=
          Outgoing Transaction Request; 'v1-out-transaction-rsp'= Outgoing Transaction
          Response; 'v1-in-quick-mode-req'= Incoming Quick Mode Request; 'v1-in-quick-
          mode-rsp'= Incoming Quick Mode Response; 'v1-out-quick-mode-req'= Outgoing
          Quick Mode Request; 'v1-out-quick-mode-rsp'= Outgoing Quick Mode Response;
          'v1-in-new-group-mode-req'= Incoming New Group Mode Request; 'v1-in-new-group-
          mode-rsp'= Incoming New Group Mode Response; 'v1-out-new-group-mode-req'=
          Outgoing New Group Mode Request; 'v1-out-new-group-mode-rsp'= Outgoing New
          Group Mode Response; 'v1-child-sa-invalid-spi'= Invalid SPI for Child SAs;
          'v2-child-sa-invalid-spi'= Invalid SPI for Child SAs; 'ike-current-version'=
          IKE version;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            remote_ip_filter:
                description:
                - "Field remote_ip_filter"
                type: str
            remote_id_filter:
                description:
                - "Field remote_id_filter"
                type: str
            brief_filter:
                description:
                - "Field brief_filter"
                type: str
            SA_List:
                description:
                - "Field SA_List"
                type: list
            name:
                description:
                - "IKE-gateway name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            v2_init_rekey:
                description:
                - "Initiate Rekey"
                type: str
            v2_rsp_rekey:
                description:
                - "Respond Rekey"
                type: str
            v2_child_sa_rekey:
                description:
                - "Child SA Rekey"
                type: str
            v2_in_invalid:
                description:
                - "Incoming Invalid"
                type: str
            v2_in_invalid_spi:
                description:
                - "Incoming Invalid SPI"
                type: str
            v2_in_init_req:
                description:
                - "Incoming Init Request"
                type: str
            v2_in_init_rsp:
                description:
                - "Incoming Init Response"
                type: str
            v2_out_init_req:
                description:
                - "Outgoing Init Request"
                type: str
            v2_out_init_rsp:
                description:
                - "Outgoing Init Response"
                type: str
            v2_in_auth_req:
                description:
                - "Incoming Auth Request"
                type: str
            v2_in_auth_rsp:
                description:
                - "Incoming Auth Response"
                type: str
            v2_out_auth_req:
                description:
                - "Outgoing Auth Request"
                type: str
            v2_out_auth_rsp:
                description:
                - "Outgoing Auth Response"
                type: str
            v2_in_create_child_req:
                description:
                - "Incoming Create Child Request"
                type: str
            v2_in_create_child_rsp:
                description:
                - "Incoming Create Child Response"
                type: str
            v2_out_create_child_req:
                description:
                - "Outgoing Create Child Request"
                type: str
            v2_out_create_child_rsp:
                description:
                - "Outgoing Create Child Response"
                type: str
            v2_in_info_req:
                description:
                - "Incoming Info Request"
                type: str
            v2_in_info_rsp:
                description:
                - "Incoming Info Response"
                type: str
            v2_out_info_req:
                description:
                - "Outgoing Info Request"
                type: str
            v2_out_info_rsp:
                description:
                - "Outgoing Info Response"
                type: str
            v1_in_id_prot_req:
                description:
                - "Incoming ID Protection Request"
                type: str
            v1_in_id_prot_rsp:
                description:
                - "Incoming ID Protection Response"
                type: str
            v1_out_id_prot_req:
                description:
                - "Outgoing ID Protection Request"
                type: str
            v1_out_id_prot_rsp:
                description:
                - "Outgoing ID Protection Response"
                type: str
            v1_in_auth_only_req:
                description:
                - "Incoming Auth Only Request"
                type: str
            v1_in_auth_only_rsp:
                description:
                - "Incoming Auth Only Response"
                type: str
            v1_out_auth_only_req:
                description:
                - "Outgoing Auth Only Request"
                type: str
            v1_out_auth_only_rsp:
                description:
                - "Outgoing Auth Only Response"
                type: str
            v1_in_aggressive_req:
                description:
                - "Incoming Aggressive Request"
                type: str
            v1_in_aggressive_rsp:
                description:
                - "Incoming Aggressive Response"
                type: str
            v1_out_aggressive_req:
                description:
                - "Outgoing Aggressive Request"
                type: str
            v1_out_aggressive_rsp:
                description:
                - "Outgoing Aggressive Response"
                type: str
            v1_in_info_v1_req:
                description:
                - "Incoming Info Request"
                type: str
            v1_in_info_v1_rsp:
                description:
                - "Incoming Info Response"
                type: str
            v1_out_info_v1_req:
                description:
                - "Outgoing Info Request"
                type: str
            v1_out_info_v1_rsp:
                description:
                - "Outgoing Info Response"
                type: str
            v1_in_transaction_req:
                description:
                - "Incoming Transaction Request"
                type: str
            v1_in_transaction_rsp:
                description:
                - "Incoming Transaction Response"
                type: str
            v1_out_transaction_req:
                description:
                - "Outgoing Transaction Request"
                type: str
            v1_out_transaction_rsp:
                description:
                - "Outgoing Transaction Response"
                type: str
            v1_in_quick_mode_req:
                description:
                - "Incoming Quick Mode Request"
                type: str
            v1_in_quick_mode_rsp:
                description:
                - "Incoming Quick Mode Response"
                type: str
            v1_out_quick_mode_req:
                description:
                - "Outgoing Quick Mode Request"
                type: str
            v1_out_quick_mode_rsp:
                description:
                - "Outgoing Quick Mode Response"
                type: str
            v1_in_new_group_mode_req:
                description:
                - "Incoming New Group Mode Request"
                type: str
            v1_in_new_group_mode_rsp:
                description:
                - "Incoming New Group Mode Response"
                type: str
            v1_out_new_group_mode_req:
                description:
                - "Outgoing New Group Mode Request"
                type: str
            v1_out_new_group_mode_rsp:
                description:
                - "Outgoing New Group Mode Response"
                type: str
            v1_child_sa_invalid_spi:
                description:
                - "Invalid SPI for Child SAs"
                type: str
            v2_child_sa_invalid_spi:
                description:
                - "Invalid SPI for Child SAs"
                type: str
            ike_current_version:
                description:
                - "IKE version"
                type: str
            name:
                description:
                - "IKE-gateway name"
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
    "auth_method", "configuration_payload", "dh_group", "dhcp_server", "disable_rekey", "dpd", "enc_cfg", "fragment_size", "hash", "ike_version", "interface_management", "key", "key_passphrase", "key_passphrase_encrypted", "lifetime", "local_address", "local_cert", "local_id", "mode", "name", "nat_traversal", "oper", "preshare_key_encrypted",
    "preshare_key_value", "radius_server", "remote_address", "remote_ca_cert", "remote_id", "sampling_enable", "stats", "user_tag", "uuid", "vrid",
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
        'ike_version': {
            'type': 'str',
            'choices': ['v1', 'v2']
            },
        'mode': {
            'type': 'str',
            'choices': ['main', 'aggressive']
            },
        'auth_method': {
            'type': 'str',
            'choices': ['preshare-key', 'rsa-signature', 'ecdsa-signature', 'eap-radius', 'eap-tls']
            },
        'preshare_key_value': {
            'type': 'str',
            },
        'preshare_key_encrypted': {
            'type': 'str',
            },
        'hash': {
            'type': 'str',
            'choices': ['sha256', 'sha384', 'sha512']
            },
        'interface_management': {
            'type': 'bool',
            },
        'key': {
            'type': 'str',
            },
        'key_passphrase': {
            'type': 'str',
            },
        'key_passphrase_encrypted': {
            'type': 'str',
            },
        'vrid': {
            'type': 'dict',
            'default': {
                'type': 'bool',
                },
            'vrid_num': {
                'type': 'int',
                }
            },
        'local_cert': {
            'type': 'dict',
            'local_cert_name': {
                'type': 'str',
                }
            },
        'remote_ca_cert': {
            'type': 'dict',
            'remote_cert_name': {
                'type': 'str',
                }
            },
        'local_id': {
            'type': 'str',
            },
        'remote_id': {
            'type': 'str',
            },
        'enc_cfg': {
            'type': 'list',
            'encryption': {
                'type': 'str',
                'choices': ['des', '3des', 'aes-128', 'aes-192', 'aes-256', 'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null']
                },
            'hash': {
                'type': 'str',
                'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
                },
            'prf': {
                'type': 'str',
                'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
                },
            'priority': {
                'type': 'int',
                },
            'gcm_priority': {
                'type': 'int',
                }
            },
        'dh_group': {
            'type': 'str',
            'choices': ['1', '2', '5', '14', '15', '16', '18', '19', '20']
            },
        'local_address': {
            'type': 'dict',
            'local_ip': {
                'type': 'str',
                },
            'local_ipv6': {
                'type': 'str',
                }
            },
        'remote_address': {
            'type': 'dict',
            'remote_ip': {
                'type': 'str',
                },
            'dns': {
                'type': 'str',
                },
            'remote_ipv6': {
                'type': 'str',
                }
            },
        'lifetime': {
            'type': 'int',
            },
        'fragment_size': {
            'type': 'int',
            },
        'nat_traversal': {
            'type': 'bool',
            },
        'dpd': {
            'type': 'dict',
            'interval': {
                'type': 'int',
                },
            'retry': {
                'type': 'int',
                }
            },
        'disable_rekey': {
            'type': 'bool',
            },
        'configuration_payload': {
            'type': 'str',
            'choices': ['dhcp', 'radius']
            },
        'dhcp_server': {
            'type': 'dict',
            'pri': {
                'type': 'dict',
                'dhcp_pri_ipv4': {
                    'type': 'str',
                    }
                },
            'sec': {
                'type': 'dict',
                'dhcp_sec_ipv4': {
                    'type': 'str',
                    }
                }
            },
        'radius_server': {
            'type': 'dict',
            'radius_pri': {
                'type': 'str',
                },
            'radius_sec': {
                'type': 'str',
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
                    'all', 'v2-init-rekey', 'v2-rsp-rekey', 'v2-child-sa-rekey', 'v2-in-invalid', 'v2-in-invalid-spi', 'v2-in-init-req', 'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp', 'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req', 'v2-out-auth-rsp', 'v2-in-create-child-req', 'v2-in-create-child-rsp', 'v2-out-create-child-req',
                    'v2-out-create-child-rsp', 'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp', 'v1-in-id-prot-req', 'v1-in-id-prot-rsp', 'v1-out-id-prot-req', 'v1-out-id-prot-rsp', 'v1-in-auth-only-req', 'v1-in-auth-only-rsp', 'v1-out-auth-only-req', 'v1-out-auth-only-rsp', 'v1-in-aggressive-req', 'v1-in-aggressive-rsp',
                    'v1-out-aggressive-req', 'v1-out-aggressive-rsp', 'v1-in-info-v1-req', 'v1-in-info-v1-rsp', 'v1-out-info-v1-req', 'v1-out-info-v1-rsp', 'v1-in-transaction-req', 'v1-in-transaction-rsp', 'v1-out-transaction-req', 'v1-out-transaction-rsp', 'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp', 'v1-out-quick-mode-req',
                    'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req', 'v1-out-new-group-mode-rsp', 'v1-child-sa-invalid-spi', 'v2-child-sa-invalid-spi', 'ike-current-version'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'remote_ip_filter': {
                'type': 'str',
                },
            'remote_id_filter': {
                'type': 'str',
                },
            'brief_filter': {
                'type': 'str',
                },
            'SA_List': {
                'type': 'list',
                'Initiator_SPI': {
                    'type': 'str',
                    },
                'Responder_SPI': {
                    'type': 'str',
                    },
                'Local_IP': {
                    'type': 'str',
                    },
                'Remote_IP': {
                    'type': 'str',
                    },
                'Encryption': {
                    'type': 'str',
                    },
                'Hash': {
                    'type': 'str',
                    },
                'Sign_hash': {
                    'type': 'str',
                    },
                'Lifetime': {
                    'type': 'int',
                    },
                'Status': {
                    'type': 'str',
                    },
                'NAT_Traversal': {
                    'type': 'int',
                    },
                'Remote_ID': {
                    'type': 'str',
                    },
                'DH_Group': {
                    'type': 'int',
                    },
                'Fragment_message_generated': {
                    'type': 'int',
                    },
                'Fragment_message_received': {
                    'type': 'int',
                    },
                'Fragmentation_error': {
                    'type': 'int',
                    },
                'Fragment_reassemble_error': {
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
            'v2_init_rekey': {
                'type': 'str',
                },
            'v2_rsp_rekey': {
                'type': 'str',
                },
            'v2_child_sa_rekey': {
                'type': 'str',
                },
            'v2_in_invalid': {
                'type': 'str',
                },
            'v2_in_invalid_spi': {
                'type': 'str',
                },
            'v2_in_init_req': {
                'type': 'str',
                },
            'v2_in_init_rsp': {
                'type': 'str',
                },
            'v2_out_init_req': {
                'type': 'str',
                },
            'v2_out_init_rsp': {
                'type': 'str',
                },
            'v2_in_auth_req': {
                'type': 'str',
                },
            'v2_in_auth_rsp': {
                'type': 'str',
                },
            'v2_out_auth_req': {
                'type': 'str',
                },
            'v2_out_auth_rsp': {
                'type': 'str',
                },
            'v2_in_create_child_req': {
                'type': 'str',
                },
            'v2_in_create_child_rsp': {
                'type': 'str',
                },
            'v2_out_create_child_req': {
                'type': 'str',
                },
            'v2_out_create_child_rsp': {
                'type': 'str',
                },
            'v2_in_info_req': {
                'type': 'str',
                },
            'v2_in_info_rsp': {
                'type': 'str',
                },
            'v2_out_info_req': {
                'type': 'str',
                },
            'v2_out_info_rsp': {
                'type': 'str',
                },
            'v1_in_id_prot_req': {
                'type': 'str',
                },
            'v1_in_id_prot_rsp': {
                'type': 'str',
                },
            'v1_out_id_prot_req': {
                'type': 'str',
                },
            'v1_out_id_prot_rsp': {
                'type': 'str',
                },
            'v1_in_auth_only_req': {
                'type': 'str',
                },
            'v1_in_auth_only_rsp': {
                'type': 'str',
                },
            'v1_out_auth_only_req': {
                'type': 'str',
                },
            'v1_out_auth_only_rsp': {
                'type': 'str',
                },
            'v1_in_aggressive_req': {
                'type': 'str',
                },
            'v1_in_aggressive_rsp': {
                'type': 'str',
                },
            'v1_out_aggressive_req': {
                'type': 'str',
                },
            'v1_out_aggressive_rsp': {
                'type': 'str',
                },
            'v1_in_info_v1_req': {
                'type': 'str',
                },
            'v1_in_info_v1_rsp': {
                'type': 'str',
                },
            'v1_out_info_v1_req': {
                'type': 'str',
                },
            'v1_out_info_v1_rsp': {
                'type': 'str',
                },
            'v1_in_transaction_req': {
                'type': 'str',
                },
            'v1_in_transaction_rsp': {
                'type': 'str',
                },
            'v1_out_transaction_req': {
                'type': 'str',
                },
            'v1_out_transaction_rsp': {
                'type': 'str',
                },
            'v1_in_quick_mode_req': {
                'type': 'str',
                },
            'v1_in_quick_mode_rsp': {
                'type': 'str',
                },
            'v1_out_quick_mode_req': {
                'type': 'str',
                },
            'v1_out_quick_mode_rsp': {
                'type': 'str',
                },
            'v1_in_new_group_mode_req': {
                'type': 'str',
                },
            'v1_in_new_group_mode_rsp': {
                'type': 'str',
                },
            'v1_out_new_group_mode_req': {
                'type': 'str',
                },
            'v1_out_new_group_mode_rsp': {
                'type': 'str',
                },
            'v1_child_sa_invalid_spi': {
                'type': 'str',
                },
            'v2_child_sa_invalid_spi': {
                'type': 'str',
                },
            'ike_current_version': {
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
    url_base = "/axapi/v3/vpn/ike-gateway/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/ike-gateway"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ike-gateway"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ike-gateway"].get(k) != v:
            change_results["changed"] = True
            config_changes["ike-gateway"][k] = v

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
    payload = utils.build_json("ike-gateway", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["ike-gateway"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ike-gateway-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["ike-gateway"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ike-gateway"]["stats"] if info != "NotFound" else info
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
