#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_vpn
description:
    - VPN Commands
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
    asymmetric_flow_support:
        description:
        - "Support asymmetric flows pass through IPsec tunnel"
        type: bool
        required: False
    stateful_mode:
        description:
        - "VPN module will work in stateful mode and create sessions"
        type: bool
        required: False
    fragment_after_encap:
        description:
        - "Fragment after adding IPsec headers"
        type: bool
        required: False
    nat_traversal_flow_affinity:
        description:
        - "Choose IPsec UDP source port based on port of inner flow (only for A10 to A10)"
        type: bool
        required: False
    tcp_mss_adjust_disable:
        description:
        - "Disable TCP MSS adjustment in SYN packet"
        type: bool
        required: False
    jumbo_fragment:
        description:
        - "Support IKE jumbo fragment packet"
        type: bool
        required: False
    ike_sa_timeout:
        description:
        - "Timeout IKE-SA in connecting state in seconds (default 600s)"
        type: int
        required: False
    ipsec_error_dump:
        description:
        - "Support record the error ipsec cavium information in dump file"
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
                - "'all'= all; 'passthrough'= passthrough; 'ha-standby-drop'= ha-standby-drop;"
                type: str
    error:
        description:
        - "Field error"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    errordump:
        description:
        - "Field errordump"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    default:
        description:
        - "Field default"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    log:
        description:
        - "Field log"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ike_stats_global:
        description:
        - "Field ike_stats_global"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ike_gateway_list:
        description:
        - "Field ike_gateway_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "IKE-gateway name"
                type: str
            ike_version:
                description:
                - "'v1'= IKEv1 key exchange; 'v2'= IKEv2 key exchange;"
                type: str
            mode:
                description:
                - "'main'= Negotiate Main mode (Default); 'aggressive'= Negotiate Aggressive mode;"
                type: str
            auth_method:
                description:
                - "'preshare-key'= Authenticate the remote gateway using a pre-shared key
          (Default); 'rsa-signature'= Authenticate the remote gateway using an RSA
          certificate; 'ecdsa-signature'= Authenticate the remote gateway using an ECDSA
          certificate;"
                type: str
            preshare_key_value:
                description:
                - "pre-shared key"
                type: str
            preshare_key_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED pre-shared key string)"
                type: str
            key:
                description:
                - "Private Key"
                type: str
            key_passphrase:
                description:
                - "Private Key Pass Phrase"
                type: str
            key_passphrase_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED key string)"
                type: str
            vrid:
                description:
                - "Field vrid"
                type: dict
            local_cert:
                description:
                - "Field local_cert"
                type: dict
            remote_ca_cert:
                description:
                - "Field remote_ca_cert"
                type: dict
            local_id:
                description:
                - "Local Gateway Identity"
                type: str
            remote_id:
                description:
                - "Remote Gateway Identity"
                type: str
            enc_cfg:
                description:
                - "Field enc_cfg"
                type: list
            dh_group:
                description:
                - "'1'= Diffie-Hellman group 1 - 768-bit(Default); '2'= Diffie-Hellman group 2 -
          1024-bit; '5'= Diffie-Hellman group 5 - 1536-bit; '14'= Diffie-Hellman group 14
          - 2048-bit; '15'= Diffie-Hellman group 15 - 3072-bit; '16'= Diffie-Hellman
          group 16 - 4096-bit; '18'= Diffie-Hellman group 18 - 8192-bit; '19'= Diffie-
          Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 -
          384-bit Elliptic Curve;"
                type: str
            local_address:
                description:
                - "Field local_address"
                type: dict
            remote_address:
                description:
                - "Field remote_address"
                type: dict
            lifetime:
                description:
                - "IKE SA age in seconds"
                type: int
            nat_traversal:
                description:
                - "Field nat_traversal"
                type: bool
            dpd:
                description:
                - "Field dpd"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ipsec_list:
        description:
        - "Field ipsec_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "IPsec name"
                type: str
            ike_gateway:
                description:
                - "Gateway to use for IPsec SA"
                type: str
            mode:
                description:
                - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default);"
                type: str
            proto:
                description:
                - "'esp'= Encapsulating security protocol (Default);"
                type: str
            dh_group:
                description:
                - "'0'= Diffie-Hellman group 0 (Default); '1'= Diffie-Hellman group 1 - 768-bits;
          '2'= Diffie-Hellman group 2 - 1024-bits; '5'= Diffie-Hellman group 5 -
          1536-bits; '14'= Diffie-Hellman group 14 - 2048-bits; '15'= Diffie-Hellman
          group 15 - 3072-bits; '16'= Diffie-Hellman group 16 - 4096-bits; '18'= Diffie-
          Hellman group 18 - 8192-bits; '19'= Diffie-Hellman group 19 - 256-bit Elliptic
          Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve;"
                type: str
            enc_cfg:
                description:
                - "Field enc_cfg"
                type: list
            lifetime:
                description:
                - "IPsec SA age in seconds"
                type: int
            lifebytes:
                description:
                - "IPsec SA age in megabytes (0 indicates unlimited bytes)"
                type: int
            anti_replay_window:
                description:
                - "'0'= Disable Anti-Replay Window Check; '32'= Window size of 32; '64'= Window
          size of 64; '128'= Window size of 128; '256'= Window size of 256; '512'= Window
          size of 512; '1024'= Window size of 1024;"
                type: str
            up:
                description:
                - "Initiates SA negotiation to bring the IPsec connection up"
                type: bool
            sequence_number_disable:
                description:
                - "Do not use incremental sequence number in the ESP header"
                type: bool
            traffic_selector:
                description:
                - "Field traffic_selector"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
            bind_tunnel:
                description:
                - "Field bind_tunnel"
                type: dict
    revocation_list:
        description:
        - "Field revocation_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Revocation name"
                type: str
            ca:
                description:
                - "Certificate Authority file name"
                type: str
            crl:
                description:
                - "Field crl"
                type: dict
            ocsp:
                description:
                - "Field ocsp"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    crl:
        description:
        - "Field crl"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ocsp:
        description:
        - "Field ocsp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ipsec_sa_by_gw:
        description:
        - "Field ipsec_sa_by_gw"
        type: dict
        required: False
        suboptions:
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
            IKE_Gateway_total:
                description:
                - "Field IKE_Gateway_total"
                type: int
            IPsec_total:
                description:
                - "Field IPsec_total"
                type: int
            IKE_SA_total:
                description:
                - "Field IKE_SA_total"
                type: int
            IPsec_SA_total:
                description:
                - "Field IPsec_SA_total"
                type: int
            IPsec_mode:
                description:
                - "Field IPsec_mode"
                type: str
            Num_hardware_devices:
                description:
                - "Field Num_hardware_devices"
                type: int
            Crypto_cores_total:
                description:
                - "Field Crypto_cores_total"
                type: int
            Crypto_cores_assigned_to_IPsec:
                description:
                - "Field Crypto_cores_assigned_to_IPsec"
                type: int
            Crypto_mem:
                description:
                - "Field Crypto_mem"
                type: int
            all_partition_list:
                description:
                - "Field all_partition_list"
                type: list
            all_partitions:
                description:
                - "Field all_partitions"
                type: bool
            shared:
                description:
                - "Field shared"
                type: bool
            specific_partition:
                description:
                - "Field specific_partition"
                type: str
            errordump:
                description:
                - "Field errordump"
                type: dict
            default:
                description:
                - "Field default"
                type: dict
            log:
                description:
                - "Field log"
                type: dict
            ike_gateway_list:
                description:
                - "Field ike_gateway_list"
                type: list
            ipsec_list:
                description:
                - "Field ipsec_list"
                type: list
            crl:
                description:
                - "Field crl"
                type: dict
            ocsp:
                description:
                - "Field ocsp"
                type: dict
            ipsec_sa_by_gw:
                description:
                - "Field ipsec_sa_by_gw"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            passthrough:
                description:
                - "Field passthrough"
                type: str
            ha_standby_drop:
                description:
                - "Field ha_standby_drop"
                type: str
            error:
                description:
                - "Field error"
                type: dict
            ike_stats_global:
                description:
                - "Field ike_stats_global"
                type: dict
            ike_gateway_list:
                description:
                - "Field ike_gateway_list"
                type: list
            ipsec_list:
                description:
                - "Field ipsec_list"
                type: list

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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule
import copy

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["asymmetric_flow_support", "crl", "default", "error", "errordump", "fragment_after_encap", "ike_gateway_list", "ike_sa_timeout", "ike_stats_global", "ipsec_error_dump", "ipsec_list", "ipsec_sa_by_gw", "jumbo_fragment", "log", "nat_traversal_flow_affinity", "ocsp", "oper", "revocation_list", "sampling_enable", "stateful_mode", "stats", "tcp_mss_adjust_disable", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'asymmetric_flow_support': {'type': 'bool', },
        'stateful_mode': {'type': 'bool', },
        'fragment_after_encap': {'type': 'bool', },
        'nat_traversal_flow_affinity': {'type': 'bool', },
        'tcp_mss_adjust_disable': {'type': 'bool', },
        'jumbo_fragment': {'type': 'bool', },
        'ike_sa_timeout': {'type': 'int', },
        'ipsec_error_dump': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'passthrough', 'ha-standby-drop']}},
        'error': {'type': 'dict', 'uuid': {'type': 'str', }},
        'errordump': {'type': 'dict', 'uuid': {'type': 'str', }},
        'default': {'type': 'dict', 'uuid': {'type': 'str', }},
        'log': {'type': 'dict', 'uuid': {'type': 'str', }},
        'ike_stats_global': {'type': 'dict', 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'v2-init-rekey', 'v2-rsp-rekey', 'v2-child-sa-rekey', 'v2-in-invalid', 'v2-in-invalid-spi', 'v2-in-init-req', 'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp', 'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req', 'v2-out-auth-rsp', 'v2-in-create-child-req', 'v2-in-create-child-rsp', 'v2-out-create-child-req', 'v2-out-create-child-rsp', 'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp', 'v1-in-id-prot-req', 'v1-in-id-prot-rsp', 'v1-out-id-prot-req', 'v1-out-id-prot-rsp', 'v1-in-auth-only-req', 'v1-in-auth-only-rsp', 'v1-out-auth-only-req', 'v1-out-auth-only-rsp', 'v1-in-aggressive-req', 'v1-in-aggressive-rsp', 'v1-out-aggressive-req', 'v1-out-aggressive-rsp', 'v1-in-info-v1-req', 'v1-in-info-v1-rsp', 'v1-out-info-v1-req', 'v1-out-info-v1-rsp', 'v1-in-transaction-req', 'v1-in-transaction-rsp', 'v1-out-transaction-req', 'v1-out-transaction-rsp', 'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp', 'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req', 'v1-out-new-group-mode-rsp']}}},
        'ike_gateway_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'ike_version': {'type': 'str', 'choices': ['v1', 'v2']}, 'mode': {'type': 'str', 'choices': ['main', 'aggressive']}, 'auth_method': {'type': 'str', 'choices': ['preshare-key', 'rsa-signature', 'ecdsa-signature']}, 'preshare_key_value': {'type': 'str', }, 'preshare_key_encrypted': {'type': 'str', }, 'key': {'type': 'str', }, 'key_passphrase': {'type': 'str', }, 'key_passphrase_encrypted': {'type': 'str', }, 'vrid': {'type': 'dict', 'vrid_num': {'type': 'int', }}, 'local_cert': {'type': 'dict', 'local_cert_name': {'type': 'str', }}, 'remote_ca_cert': {'type': 'dict', 'remote_cert_name': {'type': 'str', }}, 'local_id': {'type': 'str', }, 'remote_id': {'type': 'str', }, 'enc_cfg': {'type': 'list', 'encryption': {'type': 'str', 'choices': ['des', '3des', 'aes-128', 'aes-192', 'aes-256', 'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null']}, 'hash': {'type': 'str', 'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512']}, 'prf': {'type': 'str', 'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512']}, 'priority': {'type': 'int', }, 'gcm_priority': {'type': 'int', }}, 'dh_group': {'type': 'str', 'choices': ['1', '2', '5', '14', '15', '16', '18', '19', '20']}, 'local_address': {'type': 'dict', 'local_ip': {'type': 'str', }, 'local_ipv6': {'type': 'str', }}, 'remote_address': {'type': 'dict', 'remote_ip': {'type': 'str', }, 'dns': {'type': 'str', }, 'remote_ipv6': {'type': 'str', }}, 'lifetime': {'type': 'int', }, 'nat_traversal': {'type': 'bool', }, 'dpd': {'type': 'dict', 'interval': {'type': 'int', }, 'retry': {'type': 'int', }}, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'v2-init-rekey', 'v2-rsp-rekey', 'v2-child-sa-rekey', 'v2-in-invalid', 'v2-in-invalid-spi', 'v2-in-init-req', 'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp', 'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req', 'v2-out-auth-rsp', 'v2-in-create-child-req', 'v2-in-create-child-rsp', 'v2-out-create-child-req', 'v2-out-create-child-rsp', 'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp', 'v1-in-id-prot-req', 'v1-in-id-prot-rsp', 'v1-out-id-prot-req', 'v1-out-id-prot-rsp', 'v1-in-auth-only-req', 'v1-in-auth-only-rsp', 'v1-out-auth-only-req', 'v1-out-auth-only-rsp', 'v1-in-aggressive-req', 'v1-in-aggressive-rsp', 'v1-out-aggressive-req', 'v1-out-aggressive-rsp', 'v1-in-info-v1-req', 'v1-in-info-v1-rsp', 'v1-out-info-v1-req', 'v1-out-info-v1-rsp', 'v1-in-transaction-req', 'v1-in-transaction-rsp', 'v1-out-transaction-req', 'v1-out-transaction-rsp', 'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp', 'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req', 'v1-out-new-group-mode-rsp', 'v1-child-sa-invalid-spi', 'v2-child-sa-invalid-spi', 'ike-current-version']}}},
        'ipsec_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'ike_gateway': {'type': 'str', }, 'mode': {'type': 'str', 'choices': ['tunnel']}, 'proto': {'type': 'str', 'choices': ['esp']}, 'dh_group': {'type': 'str', 'choices': ['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']}, 'enc_cfg': {'type': 'list', 'encryption': {'type': 'str', 'choices': ['des', '3des', 'aes-128', 'aes-192', 'aes-256', 'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null']}, 'hash': {'type': 'str', 'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'null']}, 'priority': {'type': 'int', }, 'gcm_priority': {'type': 'int', }}, 'lifetime': {'type': 'int', }, 'lifebytes': {'type': 'int', }, 'anti_replay_window': {'type': 'str', 'choices': ['0', '32', '64', '128', '256', '512', '1024']}, 'up': {'type': 'bool', }, 'sequence_number_disable': {'type': 'bool', }, 'traffic_selector': {'type': 'dict', 'ipv4': {'type': 'dict', 'local': {'type': 'str', }, 'local_netmask': {'type': 'str', }, 'local_port': {'type': 'int', }, 'remote': {'type': 'str', }, 'remote_netmask': {'type': 'str', }, 'remote_port': {'type': 'int', }, 'protocol': {'type': 'int', }}, 'ipv6': {'type': 'dict', 'localv6': {'type': 'str', }, 'local_portv6': {'type': 'int', }, 'remotev6': {'type': 'str', }, 'remote_portv6': {'type': 'int', }, 'protocolv6': {'type': 'int', }}}, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'packets-encrypted', 'packets-decrypted', 'anti-replay-num', 'rekey-num', 'packets-err-inactive', 'packets-err-encryption', 'packets-err-pad-check', 'packets-err-pkt-sanity', 'packets-err-icv-check', 'packets-err-lifetime-lifebytes', 'bytes-encrypted', 'bytes-decrypted', 'prefrag-success', 'prefrag-error', 'cavium-bytes-encrypted', 'cavium-bytes-decrypted', 'cavium-packets-encrypted', 'cavium-packets-decrypted', 'tunnel-intf-down', 'pkt-fail-prep-to-send', 'no-next-hop', 'invalid-tunnel-id', 'no-tunnel-found', 'pkt-fail-to-send', 'frag-after-encap-frag-packets', 'frag-received', 'sequence-num', 'sequence-num-rollover', 'packets-err-nh-check']}}, 'bind_tunnel': {'type': 'dict', 'tunnel': {'type': 'int', }, 'next_hop': {'type': 'str', }, 'next_hop_v6': {'type': 'str', }, 'uuid': {'type': 'str', }}},
        'revocation_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'ca': {'type': 'str', }, 'crl': {'type': 'dict', 'crl_pri': {'type': 'str', }, 'crl_sec': {'type': 'str', }}, 'ocsp': {'type': 'dict', 'ocsp_pri': {'type': 'str', }, 'ocsp_sec': {'type': 'str', }}, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }},
        'crl': {'type': 'dict', 'uuid': {'type': 'str', }},
        'ocsp': {'type': 'dict', 'uuid': {'type': 'str', }},
        'ipsec_sa_by_gw': {'type': 'dict', 'uuid': {'type': 'str', }},
        'oper': {'type': 'dict', 'IKE_Gateway_total': {'type': 'int', }, 'IPsec_total': {'type': 'int', }, 'IKE_SA_total': {'type': 'int', }, 'IPsec_SA_total': {'type': 'int', }, 'IPsec_mode': {'type': 'str', }, 'Num_hardware_devices': {'type': 'int', }, 'Crypto_cores_total': {'type': 'int', }, 'Crypto_cores_assigned_to_IPsec': {'type': 'int', }, 'Crypto_mem': {'type': 'int', }, 'all_partition_list': {'type': 'list', 'IKE_Gateway_total': {'type': 'int', }, 'IPsec_total': {'type': 'int', }, 'IKE_SA_total': {'type': 'int', }, 'IPsec_SA_total': {'type': 'int', }, 'IPsec_stateless': {'type': 'int', }, 'IPsec_mode': {'type': 'str', }, 'Num_hardware_devices': {'type': 'int', }, 'Crypto_cores_total': {'type': 'int', }, 'Crypto_cores_assigned_to_IPsec': {'type': 'int', }, 'Crypto_mem': {'type': 'int', }, 'Crypto_hw_err': {'type': 'int', }, 'Crypto_hw_err_req_alloc_fail': {'type': 'int', }, 'Crypto_hw_err_enqueue_fail': {'type': 'int', }, 'Crypto_hw_err_sg_buff_alloc_fail': {'type': 'int', }, 'Crypto_hw_err_bad_pointer': {'type': 'int', }, 'Crypto_hw_err_bad_ctx_pointer': {'type': 'int', }, 'Crypto_hw_err_req_error': {'type': 'int', }, 'Crypto_hw_err_state_error': {'type': 'int', }, 'Crypto_hw_err_state': {'type': 'str', }, 'Crypto_hw_err_time_out': {'type': 'int', }, 'Crypto_hw_err_time_out_state': {'type': 'int', }, 'Crypto_hw_err_buff_alloc_error': {'type': 'int', }, 'passthrough_total': {'type': 'int', }, 'vpn_list': {'type': 'list', 'passthrough': {'type': 'int', }, 'cpu_id': {'type': 'int', }}, 'standby_drop': {'type': 'int', }, 'partition_name': {'type': 'str', }}, 'all_partitions': {'type': 'bool', }, 'shared': {'type': 'bool', }, 'specific_partition': {'type': 'str', }, 'errordump': {'type': 'dict', 'oper': {'type': 'dict', 'IPsec_error_dump_path': {'type': 'str', }}}, 'default': {'type': 'dict', 'oper': {'type': 'dict', 'ike_version': {'type': 'str', }, 'ike_mode': {'type': 'str', }, 'ike_dh_group': {'type': 'str', }, 'ike_auth_method': {'type': 'str', }, 'ike_encryption': {'type': 'str', }, 'ike_hash': {'type': 'str', }, 'ike_priority': {'type': 'int', }, 'ike_lifetime': {'type': 'int', }, 'ike_nat_traversal': {'type': 'str', }, 'ike_local_address': {'type': 'str', }, 'ike_remote_address': {'type': 'str', }, 'ike_dpd_interval': {'type': 'int', }, 'IPsec_mode': {'type': 'str', }, 'IPsec_protocol': {'type': 'str', }, 'IPsec_dh_group': {'type': 'str', }, 'IPsec_encryption': {'type': 'str', }, 'IPsec_hash': {'type': 'str', }, 'IPsec_priority': {'type': 'int', }, 'IPsec_lifetime': {'type': 'int', }, 'IPsec_lifebytes': {'type': 'int', }, 'IPsec_traffic_selector': {'type': 'str', }, 'IPsec_local_subnet': {'type': 'str', }, 'IPsec_local_port': {'type': 'int', }, 'IPsec_local_protocol': {'type': 'int', }, 'IPsec_remote_subnet': {'type': 'str', }, 'IPsec_remote_port': {'type': 'int', }, 'IPsec_remote_protocol': {'type': 'int', }, 'IPsec_anti_replay_window': {'type': 'int', }}}, 'log': {'type': 'dict', 'oper': {'type': 'dict', 'vpn_log_list': {'type': 'list', 'vpn_log_data': {'type': 'str', }}, 'vpn_log_offset': {'type': 'int', }, 'vpn_log_over': {'type': 'int', }, 'follow': {'type': 'bool', }, 'from_start': {'type': 'bool', }, 'num_lines': {'type': 'int', }}}, 'ike_gateway_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'oper': {'type': 'dict', 'Initiator_SPI': {'type': 'str', }, 'Responder_SPI': {'type': 'str', }, 'Local_IP': {'type': 'str', }, 'Remote_IP': {'type': 'str', }, 'Encryption': {'type': 'str', }, 'Hash': {'type': 'str', }, 'Lifetime': {'type': 'int', }, 'Status': {'type': 'str', }, 'NAT_Traversal': {'type': 'int', }}}, 'ipsec_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'oper': {'type': 'dict', 'Status': {'type': 'str', }, 'SA_Index': {'type': 'int', }, 'Local_IP': {'type': 'str', }, 'Peer_IP': {'type': 'str', }, 'Local_SPI': {'type': 'str', }, 'Remote_SPI': {'type': 'str', }, 'Protocol': {'type': 'str', }, 'Mode': {'type': 'str', }, 'Encryption_Algorithm': {'type': 'str', }, 'Hash_Algorithm': {'type': 'str', }, 'DH_Group': {'type': 'int', }, 'NAT_Traversal': {'type': 'int', }, 'Anti_Replay': {'type': 'str', }, 'Lifetime': {'type': 'int', }, 'Lifebytes': {'type': 'str', }}}, 'crl': {'type': 'dict', 'oper': {'type': 'dict', 'crl_list': {'type': 'list', 'subject': {'type': 'str', }, 'issuer': {'type': 'str', }, 'updates': {'type': 'str', }, 'serial': {'type': 'str', }, 'revoked': {'type': 'str', }, 'storage_type': {'type': 'str', }}, 'total_crls': {'type': 'int', }}}, 'ocsp': {'type': 'dict', 'oper': {'type': 'dict', 'ocsp_list': {'type': 'list', 'subject': {'type': 'str', }, 'issuer': {'type': 'str', }, 'validity': {'type': 'str', }, 'certificate_status': {'type': 'str', }}, 'total_ocsps': {'type': 'int', }}}, 'ipsec_sa_by_gw': {'type': 'dict', 'oper': {'type': 'dict', 'ike_gateway_name': {'type': 'str', }, 'local_ip': {'type': 'str', }, 'peer_ip': {'type': 'str', }, 'ipsec_sa_list': {'type': 'list', 'ipsec_sa_name': {'type': 'str', }, 'local_ts': {'type': 'str', }, 'remote_ts': {'type': 'str', }, 'in_spi': {'type': 'str', }, 'out_spi': {'type': 'str', }, 'protocol': {'type': 'str', }, 'mode': {'type': 'str', }, 'encryption': {'type': 'str', }, 'hash': {'type': 'str', }, 'lifetime': {'type': 'int', }, 'lifebytes': {'type': 'str', }}}}},
        'stats': {'type': 'dict', 'passthrough': {'type': 'str', }, 'ha_standby_drop': {'type': 'str', }, 'error': {'type': 'dict', 'stats': {'type': 'dict', 'bad_opcode': {'type': 'str', }, 'bad_sg_write_len': {'type': 'str', }, 'bad_len': {'type': 'str', }, 'bad_ipsec_protocol': {'type': 'str', }, 'bad_ipsec_auth': {'type': 'str', }, 'bad_ipsec_padding': {'type': 'str', }, 'bad_ip_version': {'type': 'str', }, 'bad_auth_type': {'type': 'str', }, 'bad_encrypt_type': {'type': 'str', }, 'bad_ipsec_spi': {'type': 'str', }, 'bad_checksum': {'type': 'str', }, 'bad_ipsec_context': {'type': 'str', }, 'bad_ipsec_context_direction': {'type': 'str', }, 'bad_ipsec_context_flag_mismatch': {'type': 'str', }, 'ipcomp_payload': {'type': 'str', }, 'bad_selector_match': {'type': 'str', }, 'bad_fragment_size': {'type': 'str', }, 'bad_inline_data': {'type': 'str', }, 'bad_frag_size_configuration': {'type': 'str', }, 'dummy_payload': {'type': 'str', }, 'bad_ip_payload_type': {'type': 'str', }, 'bad_min_frag_size_auth_sha384_512': {'type': 'str', }, 'bad_esp_next_header': {'type': 'str', }, 'bad_gre_header': {'type': 'str', }, 'bad_gre_protocol': {'type': 'str', }, 'ipv6_extension_headers_too_big': {'type': 'str', }, 'ipv6_hop_by_hop_error': {'type': 'str', }, 'error_ipv6_decrypt_rh_segs_left_error': {'type': 'str', }, 'ipv6_rh_length_error': {'type': 'str', }, 'ipv6_outbound_rh_copy_addr_error': {'type': 'str', }, 'error_IPv6_extension_header_bad': {'type': 'str', }, 'bad_encrypt_type_ctr_gcm': {'type': 'str', }, 'ah_not_supported_with_gcm_gmac_sha2': {'type': 'str', }, 'tfc_padding_with_prefrag_not_supported': {'type': 'str', }, 'bad_srtp_auth_tag': {'type': 'str', }, 'bad_ipcomp_configuration': {'type': 'str', }, 'dsiv_incorrect_param': {'type': 'str', }, 'bad_ipsec_unknown': {'type': 'str', }}}, 'ike_stats_global': {'type': 'dict', 'stats': {'type': 'dict', 'v2_init_rekey': {'type': 'str', }, 'v2_rsp_rekey': {'type': 'str', }, 'v2_child_sa_rekey': {'type': 'str', }, 'v2_in_invalid': {'type': 'str', }, 'v2_in_invalid_spi': {'type': 'str', }, 'v2_in_init_req': {'type': 'str', }, 'v2_in_init_rsp': {'type': 'str', }, 'v2_out_init_req': {'type': 'str', }, 'v2_out_init_rsp': {'type': 'str', }, 'v2_in_auth_req': {'type': 'str', }, 'v2_in_auth_rsp': {'type': 'str', }, 'v2_out_auth_req': {'type': 'str', }, 'v2_out_auth_rsp': {'type': 'str', }, 'v2_in_create_child_req': {'type': 'str', }, 'v2_in_create_child_rsp': {'type': 'str', }, 'v2_out_create_child_req': {'type': 'str', }, 'v2_out_create_child_rsp': {'type': 'str', }, 'v2_in_info_req': {'type': 'str', }, 'v2_in_info_rsp': {'type': 'str', }, 'v2_out_info_req': {'type': 'str', }, 'v2_out_info_rsp': {'type': 'str', }, 'v1_in_id_prot_req': {'type': 'str', }, 'v1_in_id_prot_rsp': {'type': 'str', }, 'v1_out_id_prot_req': {'type': 'str', }, 'v1_out_id_prot_rsp': {'type': 'str', }, 'v1_in_auth_only_req': {'type': 'str', }, 'v1_in_auth_only_rsp': {'type': 'str', }, 'v1_out_auth_only_req': {'type': 'str', }, 'v1_out_auth_only_rsp': {'type': 'str', }, 'v1_in_aggressive_req': {'type': 'str', }, 'v1_in_aggressive_rsp': {'type': 'str', }, 'v1_out_aggressive_req': {'type': 'str', }, 'v1_out_aggressive_rsp': {'type': 'str', }, 'v1_in_info_v1_req': {'type': 'str', }, 'v1_in_info_v1_rsp': {'type': 'str', }, 'v1_out_info_v1_req': {'type': 'str', }, 'v1_out_info_v1_rsp': {'type': 'str', }, 'v1_in_transaction_req': {'type': 'str', }, 'v1_in_transaction_rsp': {'type': 'str', }, 'v1_out_transaction_req': {'type': 'str', }, 'v1_out_transaction_rsp': {'type': 'str', }, 'v1_in_quick_mode_req': {'type': 'str', }, 'v1_in_quick_mode_rsp': {'type': 'str', }, 'v1_out_quick_mode_req': {'type': 'str', }, 'v1_out_quick_mode_rsp': {'type': 'str', }, 'v1_in_new_group_mode_req': {'type': 'str', }, 'v1_in_new_group_mode_rsp': {'type': 'str', }, 'v1_out_new_group_mode_req': {'type': 'str', }, 'v1_out_new_group_mode_rsp': {'type': 'str', }}}, 'ike_gateway_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'stats': {'type': 'dict', 'v2_init_rekey': {'type': 'str', }, 'v2_rsp_rekey': {'type': 'str', }, 'v2_child_sa_rekey': {'type': 'str', }, 'v2_in_invalid': {'type': 'str', }, 'v2_in_invalid_spi': {'type': 'str', }, 'v2_in_init_req': {'type': 'str', }, 'v2_in_init_rsp': {'type': 'str', }, 'v2_out_init_req': {'type': 'str', }, 'v2_out_init_rsp': {'type': 'str', }, 'v2_in_auth_req': {'type': 'str', }, 'v2_in_auth_rsp': {'type': 'str', }, 'v2_out_auth_req': {'type': 'str', }, 'v2_out_auth_rsp': {'type': 'str', }, 'v2_in_create_child_req': {'type': 'str', }, 'v2_in_create_child_rsp': {'type': 'str', }, 'v2_out_create_child_req': {'type': 'str', }, 'v2_out_create_child_rsp': {'type': 'str', }, 'v2_in_info_req': {'type': 'str', }, 'v2_in_info_rsp': {'type': 'str', }, 'v2_out_info_req': {'type': 'str', }, 'v2_out_info_rsp': {'type': 'str', }, 'v1_in_id_prot_req': {'type': 'str', }, 'v1_in_id_prot_rsp': {'type': 'str', }, 'v1_out_id_prot_req': {'type': 'str', }, 'v1_out_id_prot_rsp': {'type': 'str', }, 'v1_in_auth_only_req': {'type': 'str', }, 'v1_in_auth_only_rsp': {'type': 'str', }, 'v1_out_auth_only_req': {'type': 'str', }, 'v1_out_auth_only_rsp': {'type': 'str', }, 'v1_in_aggressive_req': {'type': 'str', }, 'v1_in_aggressive_rsp': {'type': 'str', }, 'v1_out_aggressive_req': {'type': 'str', }, 'v1_out_aggressive_rsp': {'type': 'str', }, 'v1_in_info_v1_req': {'type': 'str', }, 'v1_in_info_v1_rsp': {'type': 'str', }, 'v1_out_info_v1_req': {'type': 'str', }, 'v1_out_info_v1_rsp': {'type': 'str', }, 'v1_in_transaction_req': {'type': 'str', }, 'v1_in_transaction_rsp': {'type': 'str', }, 'v1_out_transaction_req': {'type': 'str', }, 'v1_out_transaction_rsp': {'type': 'str', }, 'v1_in_quick_mode_req': {'type': 'str', }, 'v1_in_quick_mode_rsp': {'type': 'str', }, 'v1_out_quick_mode_req': {'type': 'str', }, 'v1_out_quick_mode_rsp': {'type': 'str', }, 'v1_in_new_group_mode_req': {'type': 'str', }, 'v1_in_new_group_mode_rsp': {'type': 'str', }, 'v1_out_new_group_mode_req': {'type': 'str', }, 'v1_out_new_group_mode_rsp': {'type': 'str', }, 'v1_child_sa_invalid_spi': {'type': 'str', }, 'v2_child_sa_invalid_spi': {'type': 'str', }, 'ike_current_version': {'type': 'str', }}}, 'ipsec_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'stats': {'type': 'dict', 'packets_encrypted': {'type': 'str', }, 'packets_decrypted': {'type': 'str', }, 'anti_replay_num': {'type': 'str', }, 'rekey_num': {'type': 'str', }, 'packets_err_inactive': {'type': 'str', }, 'packets_err_encryption': {'type': 'str', }, 'packets_err_pad_check': {'type': 'str', }, 'packets_err_pkt_sanity': {'type': 'str', }, 'packets_err_icv_check': {'type': 'str', }, 'packets_err_lifetime_lifebytes': {'type': 'str', }, 'bytes_encrypted': {'type': 'str', }, 'bytes_decrypted': {'type': 'str', }, 'prefrag_success': {'type': 'str', }, 'prefrag_error': {'type': 'str', }, 'cavium_bytes_encrypted': {'type': 'str', }, 'cavium_bytes_decrypted': {'type': 'str', }, 'cavium_packets_encrypted': {'type': 'str', }, 'cavium_packets_decrypted': {'type': 'str', }, 'tunnel_intf_down': {'type': 'str', }, 'pkt_fail_prep_to_send': {'type': 'str', }, 'no_next_hop': {'type': 'str', }, 'invalid_tunnel_id': {'type': 'str', }, 'no_tunnel_found': {'type': 'str', }, 'pkt_fail_to_send': {'type': 'str', }, 'frag_after_encap_frag_packets': {'type': 'str', }, 'frag_received': {'type': 'str', }, 'sequence_num': {'type': 'str', }, 'sequence_num_rollover': {'type': 'str', }, 'packets_err_nh_check': {'type': 'str', }}}}
    })
    return rv


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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {"device-id": device_id},
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {"curr_part_name": a10_partition},
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)



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
    return {
        title: data
    }


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results


    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["vpn"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["vpn"].get(k) != v:
            change_results["changed"] = True
            config_changes["vpn"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(
                **call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(
                **call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("vpn", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
    )

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

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(
            _active_partition(module, a10_partition))

    if a10_device_context_id:
         result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
