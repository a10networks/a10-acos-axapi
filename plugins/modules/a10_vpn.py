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
    ike_acc_enable:
        description:
        - "Enable IKE Acceleration by Cavium Nitrox card"
        type: bool
        required: False
    ike_logging_enable:
        description:
        - "Enable IKE negotiation logging"
        type: bool
        required: False
    ipsec_error_dump:
        description:
        - "Support record the error ipsec cavium information in dump file"
        type: bool
        required: False
    ipsec_mgmt_default_policy_drop:
        description:
        - "Drop MGMT traffic that is not match ipsec tunnel, share partition only"
        type: bool
        required: False
    extended_matching:
        description:
        - "Enable session extended matching for packet comes from IPsec tunnel"
        type: bool
        required: False
    enable_vpn_metrics:
        description:
        - "Enable exporting vpn statstics to Harmony"
        type: bool
        required: False
    ipsec_cipher_check:
        description:
        - "Enable cipher check, IPsec SA cipher must weaker than IKE gateway cipher, and
          DES/3DES/MD5/null will not work."
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
          certificate; 'eap-radius'= Authenticate the remote gateway using an EAP Radius
          server; 'eap-tls'= Authenticate the remote gateway using EAP TLS;"
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
            interface_management:
                description:
                - "only handle traffic on management interface, share partition only"
                type: bool
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
            fragment_size:
                description:
                - "Enable IKE message fragment and set fragment size"
                type: int
            nat_traversal:
                description:
                - "Field nat_traversal"
                type: bool
            dpd:
                description:
                - "Field dpd"
                type: dict
            disable_rekey:
                description:
                - "Disable initiating rekey"
                type: bool
            configuration_payload:
                description:
                - "'dhcp'= Enable DHCP configuration-payload; 'radius'= Enable RADIUS
          configuration-payload;"
                type: str
            dhcp_server:
                description:
                - "Field dhcp_server"
                type: dict
            radius_server:
                description:
                - "Field radius_server"
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
            mode:
                description:
                - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default);"
                type: str
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
          size of 512; '1024'= Window size of 1024; '2048'= Window size of 2048; '3072'=
          Window size of 3072; '4096'= Window size of 4096; '8192'= Window size of 8192;"
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
            enforce_traffic_selector:
                description:
                - "Enforce Traffic Selector"
                type: bool
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
            ipsec_gateway:
                description:
                - "Field ipsec_gateway"
                type: dict
    ipsec_group_list:
        description:
        - "Field ipsec_group_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Group name"
                type: str
            ipsecgroup_cfg:
                description:
                - "Field ipsecgroup_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    group_list:
        description:
        - "Field group_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ipsec_sa_stats_list:
        description:
        - "Field ipsec_sa_stats_list"
        type: list
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
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
    ike_sa:
        description:
        - "Field ike_sa"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ipsec_sa:
        description:
        - "Field ipsec_sa"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ike_sa_brief:
        description:
        - "Field ike_sa_brief"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ike_sa_clients:
        description:
        - "Field ike_sa_clients"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ipsec_sa_clients:
        description:
        - "Field ipsec_sa_clients"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ike_stats_by_gw:
        description:
        - "Field ike_stats_by_gw"
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
            group_list:
                description:
                - "Field group_list"
                type: dict
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
            ike_sa:
                description:
                - "Field ike_sa"
                type: dict
            ipsec_sa:
                description:
                - "Field ipsec_sa"
                type: dict
            ike_sa_brief:
                description:
                - "Field ike_sa_brief"
                type: dict
            ike_sa_clients:
                description:
                - "Field ike_sa_clients"
                type: dict
            ipsec_sa_clients:
                description:
                - "Field ipsec_sa_clients"
                type: dict
            ike_stats_by_gw:
                description:
                - "Field ike_stats_by_gw"
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
            ipsec_sa_stats_list:
                description:
                - "Field ipsec_sa_stats_list"
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
    "asymmetric_flow_support", "crl", "default", "enable_vpn_metrics", "error", "errordump", "extended_matching", "fragment_after_encap", "group_list", "ike_acc_enable", "ike_gateway_list", "ike_logging_enable", "ike_sa", "ike_sa_brief", "ike_sa_clients", "ike_sa_timeout", "ike_stats_by_gw", "ike_stats_global", "ipsec_cipher_check",
    "ipsec_error_dump", "ipsec_group_list", "ipsec_list", "ipsec_mgmt_default_policy_drop", "ipsec_sa", "ipsec_sa_by_gw", "ipsec_sa_clients", "ipsec_sa_stats_list", "jumbo_fragment", "log", "nat_traversal_flow_affinity", "ocsp", "oper", "revocation_list", "sampling_enable", "stateful_mode", "stats", "tcp_mss_adjust_disable", "uuid",
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
        'asymmetric_flow_support': {
            'type': 'bool',
            },
        'stateful_mode': {
            'type': 'bool',
            },
        'fragment_after_encap': {
            'type': 'bool',
            },
        'nat_traversal_flow_affinity': {
            'type': 'bool',
            },
        'tcp_mss_adjust_disable': {
            'type': 'bool',
            },
        'jumbo_fragment': {
            'type': 'bool',
            },
        'ike_sa_timeout': {
            'type': 'int',
            },
        'ike_acc_enable': {
            'type': 'bool',
            },
        'ike_logging_enable': {
            'type': 'bool',
            },
        'ipsec_error_dump': {
            'type': 'bool',
            },
        'ipsec_mgmt_default_policy_drop': {
            'type': 'bool',
            },
        'extended_matching': {
            'type': 'bool',
            },
        'enable_vpn_metrics': {
            'type': 'bool',
            },
        'ipsec_cipher_check': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type': 'str',
                'choices': ['all', 'passthrough', 'ha-standby-drop']
                }
            },
        'error': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'errordump': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'default': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'log': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ike_stats_global': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'v2-init-rekey', 'v2-rsp-rekey', 'v2-child-sa-rekey', 'v2-in-invalid', 'v2-in-invalid-spi', 'v2-in-init-req', 'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp', 'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req', 'v2-out-auth-rsp', 'v2-in-create-child-req', 'v2-in-create-child-rsp', 'v2-out-create-child-req',
                        'v2-out-create-child-rsp', 'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp', 'v1-in-id-prot-req', 'v1-in-id-prot-rsp', 'v1-out-id-prot-req', 'v1-out-id-prot-rsp', 'v1-in-auth-only-req', 'v1-in-auth-only-rsp', 'v1-out-auth-only-req', 'v1-out-auth-only-rsp', 'v1-in-aggressive-req',
                        'v1-in-aggressive-rsp', 'v1-out-aggressive-req', 'v1-out-aggressive-rsp', 'v1-in-info-v1-req', 'v1-in-info-v1-rsp', 'v1-out-info-v1-req', 'v1-out-info-v1-rsp', 'v1-in-transaction-req', 'v1-in-transaction-rsp', 'v1-out-transaction-req', 'v1-out-transaction-rsp', 'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp',
                        'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req', 'v1-out-new-group-mode-rsp'
                        ]
                    }
                }
            },
        'ike_gateway_list': {
            'type': 'list',
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
                        'v2-out-create-child-rsp', 'v2-in-info-req', 'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp', 'v1-in-id-prot-req', 'v1-in-id-prot-rsp', 'v1-out-id-prot-req', 'v1-out-id-prot-rsp', 'v1-in-auth-only-req', 'v1-in-auth-only-rsp', 'v1-out-auth-only-req', 'v1-out-auth-only-rsp', 'v1-in-aggressive-req',
                        'v1-in-aggressive-rsp', 'v1-out-aggressive-req', 'v1-out-aggressive-rsp', 'v1-in-info-v1-req', 'v1-in-info-v1-rsp', 'v1-out-info-v1-req', 'v1-out-info-v1-rsp', 'v1-in-transaction-req', 'v1-in-transaction-rsp', 'v1-out-transaction-req', 'v1-out-transaction-rsp', 'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp',
                        'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp', 'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp', 'v1-out-new-group-mode-req', 'v1-out-new-group-mode-rsp', 'v1-child-sa-invalid-spi', 'v2-child-sa-invalid-spi', 'ike-current-version'
                        ]
                    }
                }
            },
        'ipsec_list': {
            'type': 'list',
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
                    'default', 'af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28',
                    '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63'
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
                }
            },
        'ipsec_group_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'ipsecgroup_cfg': {
                'type': 'list',
                'ipsec': {
                    'type': 'str',
                    },
                'priority': {
                    'type': 'int',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'group_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ipsec_sa_stats_list': {
            'type': 'list',
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
                }
            },
        'revocation_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'ca': {
                'type': 'str',
                },
            'crl': {
                'type': 'dict',
                'crl_pri': {
                    'type': 'str',
                    },
                'crl_sec': {
                    'type': 'str',
                    }
                },
            'ocsp': {
                'type': 'dict',
                'ocsp_pri': {
                    'type': 'str',
                    },
                'ocsp_sec': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'crl': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ocsp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ipsec_sa_by_gw': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ike_sa': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ipsec_sa': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ike_sa_brief': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ike_sa_clients': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ipsec_sa_clients': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ike_stats_by_gw': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'IKE_Gateway_total': {
                'type': 'int',
                },
            'IPsec_total': {
                'type': 'int',
                },
            'IKE_SA_total': {
                'type': 'int',
                },
            'IPsec_SA_total': {
                'type': 'int',
                },
            'IPsec_mode': {
                'type': 'str',
                },
            'Num_hardware_devices': {
                'type': 'int',
                },
            'Crypto_cores_total': {
                'type': 'int',
                },
            'Crypto_cores_assigned_to_IPsec': {
                'type': 'int',
                },
            'Crypto_mem': {
                'type': 'int',
                },
            'all_partition_list': {
                'type': 'list',
                'IKE_Gateway_total': {
                    'type': 'int',
                    },
                'IPsec_total': {
                    'type': 'int',
                    },
                'IKE_SA_total': {
                    'type': 'int',
                    },
                'IPsec_SA_total': {
                    'type': 'int',
                    },
                'IPsec_stateless': {
                    'type': 'int',
                    },
                'IPsec_mode': {
                    'type': 'str',
                    },
                'IPsec_hardware_type': {
                    'type': 'str',
                    },
                'Num_hardware_devices': {
                    'type': 'int',
                    },
                'IKE_hardware_accelerate': {
                    'type': 'str',
                    },
                'Crypto_cores_total': {
                    'type': 'int',
                    },
                'Crypto_cores_assigned_to_IPsec': {
                    'type': 'int',
                    },
                'Crypto_mem': {
                    'type': 'int',
                    },
                'Crypto_hw_err': {
                    'type': 'int',
                    },
                'Crypto_hw_err_req_alloc_fail': {
                    'type': 'int',
                    },
                'Crypto_hw_err_enqueue_fail': {
                    'type': 'int',
                    },
                'Crypto_hw_err_sg_buff_alloc_fail': {
                    'type': 'int',
                    },
                'Crypto_hw_err_bad_pointer': {
                    'type': 'int',
                    },
                'Crypto_hw_err_bad_ctx_pointer': {
                    'type': 'int',
                    },
                'Crypto_hw_err_req_error': {
                    'type': 'int',
                    },
                'Crypto_hw_err_state_error': {
                    'type': 'int',
                    },
                'Crypto_hw_err_state': {
                    'type': 'str',
                    },
                'Crypto_hw_err_time_out': {
                    'type': 'int',
                    },
                'Crypto_hw_err_time_out_state': {
                    'type': 'int',
                    },
                'Crypto_hw_err_buff_alloc_error': {
                    'type': 'int',
                    },
                'passthrough_total': {
                    'type': 'int',
                    },
                'vpn_list': {
                    'type': 'list',
                    'passthrough': {
                        'type': 'int',
                        },
                    'cpu_id': {
                        'type': 'int',
                        }
                    },
                'standby_drop': {
                    'type': 'int',
                    },
                'partition_name': {
                    'type': 'str',
                    }
                },
            'all_partitions': {
                'type': 'bool',
                },
            'shared': {
                'type': 'bool',
                },
            'specific_partition': {
                'type': 'str',
                },
            'errordump': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'IPsec_error_dump_path': {
                        'type': 'str',
                        }
                    }
                },
            'default': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ike_version': {
                        'type': 'str',
                        },
                    'ike_mode': {
                        'type': 'str',
                        },
                    'ike_dh_group': {
                        'type': 'str',
                        },
                    'ike_auth_method': {
                        'type': 'str',
                        },
                    'ike_encryption': {
                        'type': 'str',
                        },
                    'ike_hash': {
                        'type': 'str',
                        },
                    'ike_priority': {
                        'type': 'int',
                        },
                    'ike_lifetime': {
                        'type': 'int',
                        },
                    'ike_nat_traversal': {
                        'type': 'str',
                        },
                    'ike_local_address': {
                        'type': 'str',
                        },
                    'ike_remote_address': {
                        'type': 'str',
                        },
                    'ike_dpd_interval': {
                        'type': 'int',
                        },
                    'IPsec_mode': {
                        'type': 'str',
                        },
                    'IPsec_protocol': {
                        'type': 'str',
                        },
                    'IPsec_dh_group': {
                        'type': 'str',
                        },
                    'IPsec_encryption': {
                        'type': 'str',
                        },
                    'IPsec_hash': {
                        'type': 'str',
                        },
                    'IPsec_priority': {
                        'type': 'int',
                        },
                    'IPsec_lifetime': {
                        'type': 'int',
                        },
                    'IPsec_lifebytes': {
                        'type': 'int',
                        },
                    'IPsec_traffic_selector': {
                        'type': 'str',
                        },
                    'IPsec_local_subnet': {
                        'type': 'str',
                        },
                    'IPsec_local_port': {
                        'type': 'int',
                        },
                    'IPsec_local_protocol': {
                        'type': 'int',
                        },
                    'IPsec_remote_subnet': {
                        'type': 'str',
                        },
                    'IPsec_remote_port': {
                        'type': 'int',
                        },
                    'IPsec_remote_protocol': {
                        'type': 'int',
                        },
                    'IPsec_anti_replay_window': {
                        'type': 'int',
                        }
                    }
                },
            'log': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'vpn_log_list': {
                        'type': 'list',
                        'vpn_log_data': {
                            'type': 'str',
                            }
                        },
                    'vpn_log_offset': {
                        'type': 'int',
                        },
                    'vpn_log_over': {
                        'type': 'int',
                        },
                    'follow': {
                        'type': 'bool',
                        },
                    'from_start': {
                        'type': 'bool',
                        },
                    'num_lines': {
                        'type': 'int',
                        }
                    }
                },
            'ike_gateway_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
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
                        }
                    }
                },
            'ipsec_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
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
                            'type': 'str',
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
                        }
                    }
                },
            'group_list': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'group_name': {
                        'type': 'str',
                        },
                    'group_list': {
                        'type': 'list',
                        'Name': {
                            'type': 'str',
                            },
                        'Ipsec_sa_name': {
                            'type': 'str',
                            },
                        'Ike_gateway_name': {
                            'type': 'str',
                            },
                        'Priority': {
                            'type': 'int',
                            },
                        'Status': {
                            'type': 'str',
                            },
                        'Role': {
                            'type': 'str',
                            },
                        'Is_new_group': {
                            'type': 'int',
                            },
                        'Grp_member_count': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'crl': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'crl_list': {
                        'type': 'list',
                        'subject': {
                            'type': 'str',
                            },
                        'issuer': {
                            'type': 'str',
                            },
                        'updates': {
                            'type': 'str',
                            },
                        'serial': {
                            'type': 'str',
                            },
                        'revoked': {
                            'type': 'str',
                            },
                        'storage_type': {
                            'type': 'str',
                            }
                        },
                    'total_crls': {
                        'type': 'int',
                        }
                    }
                },
            'ocsp': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ocsp_list': {
                        'type': 'list',
                        'subject': {
                            'type': 'str',
                            },
                        'issuer': {
                            'type': 'str',
                            },
                        'validity': {
                            'type': 'str',
                            },
                        'certificate_status': {
                            'type': 'str',
                            }
                        },
                    'total_ocsps': {
                        'type': 'int',
                        }
                    }
                },
            'ipsec_sa_by_gw': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ike_gateway_name': {
                        'type': 'str',
                        },
                    'local_ip': {
                        'type': 'str',
                        },
                    'peer_ip': {
                        'type': 'str',
                        },
                    'ipsec_sa_list': {
                        'type': 'list',
                        'ipsec_sa_name': {
                            'type': 'str',
                            },
                        'local_ts': {
                            'type': 'str',
                            },
                        'remote_ts': {
                            'type': 'str',
                            },
                        'in_spi': {
                            'type': 'str',
                            },
                        'out_spi': {
                            'type': 'str',
                            },
                        'protocol': {
                            'type': 'str',
                            },
                        'mode': {
                            'type': 'str',
                            },
                        'encryption': {
                            'type': 'str',
                            },
                        'hash': {
                            'type': 'str',
                            },
                        'lifetime': {
                            'type': 'int',
                            },
                        'lifebytes': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'ike_sa': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ike_sa_list': {
                        'type': 'list',
                        'Name': {
                            'type': 'str',
                            },
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
                        'Lifetime': {
                            'type': 'int',
                            },
                        'Status': {
                            'type': 'str',
                            },
                        'NAT_Traversal': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'ipsec_sa': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ipsec_sa_list': {
                        'type': 'list',
                        'ipsec_sa_name': {
                            'type': 'str',
                            },
                        'ike_gateway_name': {
                            'type': 'str',
                            },
                        'local_ts': {
                            'type': 'str',
                            },
                        'remote_ts': {
                            'type': 'str',
                            },
                        'in_spi': {
                            'type': 'str',
                            },
                        'out_spi': {
                            'type': 'str',
                            },
                        'protocol': {
                            'type': 'str',
                            },
                        'mode': {
                            'type': 'str',
                            },
                        'encryption': {
                            'type': 'str',
                            },
                        'hash': {
                            'type': 'str',
                            },
                        'lifetime': {
                            'type': 'int',
                            },
                        'lifebytes': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'ike_sa_brief': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                        },
                    'local_ip': {
                        'type': 'str',
                        },
                    'ike_sa_brief_remote_gw': {
                        'type': 'list',
                        'ike_sa_brief_remote_gw_ip': {
                            'type': 'str',
                            },
                        'ike_sa_brief_remote_gw_id': {
                            'type': 'str',
                            },
                        'ike_sa_brief_remote_gw_lifetime': {
                            'type': 'str',
                            },
                        'ike_sa_brief_remote_gw_status': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'ike_sa_clients': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                        },
                    'ike_sa_clients_local_ip': {
                        'type': 'str',
                        },
                    'ike_sa_clients_remote_gw': {
                        'type': 'list',
                        'ike_sa_clients_remote_gw_ip': {
                            'type': 'str',
                            },
                        'ike_sa_clients_remote_gw_remote_id': {
                            'type': 'str',
                            },
                        'ike_sa_clients_remote_gw_user_id': {
                            'type': 'str',
                            },
                        'ike_sa_clients_remote_gw_idle_time': {
                            'type': 'str',
                            },
                        'ike_sa_clients_remote_gw_session_time': {
                            'type': 'str',
                            },
                        'ike_sa_clients_remote_gw_bytes': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'ipsec_sa_clients': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ipsec_clients': {
                        'type': 'list',
                        'ipsec_clients_ip': {
                            'type': 'str',
                            },
                        'sa_list': {
                            'type': 'list',
                            'name': {
                                'type': 'str',
                                },
                            'local_ts': {
                                'type': 'str',
                                },
                            'in_spi': {
                                'type': 'str',
                                },
                            'out_spi': {
                                'type': 'str',
                                },
                            'lifetime': {
                                'type': 'str',
                                },
                            'lifebytes': {
                                'type': 'str',
                                }
                            }
                        }
                    }
                },
            'ike_stats_by_gw': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'gateway_name_filter': {
                        'type': 'str',
                        },
                    'remote_ip_filter': {
                        'type': 'str',
                        },
                    'remote_id_filter': {
                        'type': 'str',
                        },
                    'display_all_filter': {
                        'type': 'bool',
                        },
                    'ike_stats_list': {
                        'type': 'list',
                        'name': {
                            'type': 'str',
                            },
                        'remote_id': {
                            'type': 'str',
                            },
                        'remote_ip': {
                            'type': 'str',
                            },
                        'ike_version': {
                            'type': 'str',
                            },
                        'v1_in_id_prot_req': {
                            'type': 'int',
                            },
                        'v1_in_id_prot_rsp': {
                            'type': 'int',
                            },
                        'v1_out_id_prot_req': {
                            'type': 'int',
                            },
                        'v1_out_id_prot_rsp': {
                            'type': 'int',
                            },
                        'v1_in_auth_only_req': {
                            'type': 'int',
                            },
                        'v1_in_auth_only_rsp': {
                            'type': 'int',
                            },
                        'v1_out_auth_only_req': {
                            'type': 'int',
                            },
                        'v1_out_auth_only_rsp': {
                            'type': 'int',
                            },
                        'v1_in_aggressive_req': {
                            'type': 'int',
                            },
                        'v1_in_aggressive_rsp': {
                            'type': 'int',
                            },
                        'v1_out_aggressive_req': {
                            'type': 'int',
                            },
                        'v1_out_aggressive_rsp': {
                            'type': 'int',
                            },
                        'v1_in_info_v1_req': {
                            'type': 'int',
                            },
                        'v1_in_info_v1_rsp': {
                            'type': 'int',
                            },
                        'v1_out_info_v1_req': {
                            'type': 'int',
                            },
                        'v1_out_info_v1_rsp': {
                            'type': 'int',
                            },
                        'v1_in_transaction_req': {
                            'type': 'int',
                            },
                        'v1_in_transaction_rsp': {
                            'type': 'int',
                            },
                        'v1_out_transaction_req': {
                            'type': 'int',
                            },
                        'v1_out_transaction_rsp': {
                            'type': 'int',
                            },
                        'v1_in_quick_mode_req': {
                            'type': 'int',
                            },
                        'v1_in_quick_mode_rsp': {
                            'type': 'int',
                            },
                        'v1_out_quick_mode_req': {
                            'type': 'int',
                            },
                        'v1_out_quick_mode_rsp': {
                            'type': 'int',
                            },
                        'v1_in_new_group_mode_req': {
                            'type': 'int',
                            },
                        'v1_in_new_group_mode_rsp': {
                            'type': 'int',
                            },
                        'v1_out_new_group_mode_req': {
                            'type': 'int',
                            },
                        'v1_out_new_group_mode_rsp': {
                            'type': 'int',
                            },
                        'v1_child_sa_invalid_spi': {
                            'type': 'int',
                            },
                        'v2_init_rekey': {
                            'type': 'int',
                            },
                        'v2_rsp_rekey': {
                            'type': 'int',
                            },
                        'v2_child_sa_rekey': {
                            'type': 'int',
                            },
                        'v2_in_invalid': {
                            'type': 'int',
                            },
                        'v2_in_invalid_spi': {
                            'type': 'int',
                            },
                        'v2_in_init_req': {
                            'type': 'int',
                            },
                        'v2_in_init_rsp': {
                            'type': 'int',
                            },
                        'v2_out_init_req': {
                            'type': 'int',
                            },
                        'v2_out_init_rsp': {
                            'type': 'int',
                            },
                        'v2_in_auth_req': {
                            'type': 'int',
                            },
                        'v2_in_auth_rsp': {
                            'type': 'int',
                            },
                        'v2_out_auth_req': {
                            'type': 'int',
                            },
                        'v2_out_auth_rsp': {
                            'type': 'int',
                            },
                        'v2_in_create_child_req': {
                            'type': 'int',
                            },
                        'v2_in_create_child_rsp': {
                            'type': 'int',
                            },
                        'v2_out_create_child_req': {
                            'type': 'int',
                            },
                        'v2_out_create_child_rsp': {
                            'type': 'int',
                            },
                        'v2_in_info_req': {
                            'type': 'int',
                            },
                        'v2_in_info_rsp': {
                            'type': 'int',
                            },
                        'v2_out_info_req': {
                            'type': 'int',
                            },
                        'v2_out_info_rsp': {
                            'type': 'int',
                            },
                        'v2_child_sa_invalid_spi': {
                            'type': 'int',
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'passthrough': {
                'type': 'str',
                },
            'ha_standby_drop': {
                'type': 'str',
                },
            'error': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'bad_opcode': {
                        'type': 'str',
                        },
                    'bad_sg_write_len': {
                        'type': 'str',
                        },
                    'bad_len': {
                        'type': 'str',
                        },
                    'bad_ipsec_protocol': {
                        'type': 'str',
                        },
                    'bad_ipsec_auth': {
                        'type': 'str',
                        },
                    'bad_ipsec_padding': {
                        'type': 'str',
                        },
                    'bad_ip_version': {
                        'type': 'str',
                        },
                    'bad_auth_type': {
                        'type': 'str',
                        },
                    'bad_encrypt_type': {
                        'type': 'str',
                        },
                    'bad_ipsec_spi': {
                        'type': 'str',
                        },
                    'bad_checksum': {
                        'type': 'str',
                        },
                    'bad_ipsec_context': {
                        'type': 'str',
                        },
                    'bad_ipsec_context_direction': {
                        'type': 'str',
                        },
                    'bad_ipsec_context_flag_mismatch': {
                        'type': 'str',
                        },
                    'ipcomp_payload': {
                        'type': 'str',
                        },
                    'bad_selector_match': {
                        'type': 'str',
                        },
                    'bad_fragment_size': {
                        'type': 'str',
                        },
                    'bad_inline_data': {
                        'type': 'str',
                        },
                    'bad_frag_size_configuration': {
                        'type': 'str',
                        },
                    'dummy_payload': {
                        'type': 'str',
                        },
                    'bad_ip_payload_type': {
                        'type': 'str',
                        },
                    'bad_min_frag_size_auth_sha384_512': {
                        'type': 'str',
                        },
                    'bad_esp_next_header': {
                        'type': 'str',
                        },
                    'bad_gre_header': {
                        'type': 'str',
                        },
                    'bad_gre_protocol': {
                        'type': 'str',
                        },
                    'ipv6_extension_headers_too_big': {
                        'type': 'str',
                        },
                    'ipv6_hop_by_hop_error': {
                        'type': 'str',
                        },
                    'error_ipv6_decrypt_rh_segs_left_error': {
                        'type': 'str',
                        },
                    'ipv6_rh_length_error': {
                        'type': 'str',
                        },
                    'ipv6_outbound_rh_copy_addr_error': {
                        'type': 'str',
                        },
                    'error_IPv6_extension_header_bad': {
                        'type': 'str',
                        },
                    'bad_encrypt_type_ctr_gcm': {
                        'type': 'str',
                        },
                    'ah_not_supported_with_gcm_gmac_sha2': {
                        'type': 'str',
                        },
                    'tfc_padding_with_prefrag_not_supported': {
                        'type': 'str',
                        },
                    'bad_srtp_auth_tag': {
                        'type': 'str',
                        },
                    'bad_ipcomp_configuration': {
                        'type': 'str',
                        },
                    'dsiv_incorrect_param': {
                        'type': 'str',
                        },
                    'bad_ipsec_unknown': {
                        'type': 'str',
                        }
                    }
                },
            'ike_stats_global': {
                'type': 'dict',
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
                        }
                    }
                },
            'ike_gateway_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
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
                        }
                    }
                },
            'ipsec_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
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
                        }
                    }
                },
            'ipsec_sa_stats_list': {
                'type': 'list',
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
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn"

    f_dict = {}

    return url_base.format(**f_dict)


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
    payload = utils.build_json("vpn", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["vpn"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["vpn-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["vpn"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["vpn"]["stats"] if info != "NotFound" else info
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
