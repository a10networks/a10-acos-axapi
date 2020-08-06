#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            ipsec_sa_by_gw:
                description:
                - "Field ipsec_sa_by_gw"
            ipsec_list:
                description:
                - "Field ipsec_list"
            all_partitions:
                description:
                - "Field all_partitions"
            Num_hardware_devices:
                description:
                - "Field Num_hardware_devices"
            IPsec_mode:
                description:
                - "Field IPsec_mode"
            specific_partition:
                description:
                - "Field specific_partition"
            IKE_Gateway_total:
                description:
                - "Field IKE_Gateway_total"
            ike_gateway_list:
                description:
                - "Field ike_gateway_list"
            all_partition_list:
                description:
                - "Field all_partition_list"
            IPsec_SA_total:
                description:
                - "Field IPsec_SA_total"
            default:
                description:
                - "Field default"
            Crypto_cores_assigned_to_IPsec:
                description:
                - "Field Crypto_cores_assigned_to_IPsec"
            IKE_SA_total:
                description:
                - "Field IKE_SA_total"
            errordump:
                description:
                - "Field errordump"
            Crypto_cores_total:
                description:
                - "Field Crypto_cores_total"
            IPsec_total:
                description:
                - "Field IPsec_total"
            shared:
                description:
                - "Field shared"
            ocsp:
                description:
                - "Field ocsp"
            Crypto_mem:
                description:
                - "Field Crypto_mem"
            crl:
                description:
                - "Field crl"
            log:
                description:
                - "Field log"
    tcp_mss_adjust_disable:
        description:
        - "Disable TCP MSS adjustment in SYN packet"
        required: False
    ike_gateway_list:
        description:
        - "Field ike_gateway_list"
        required: False
        suboptions:
            ike_version:
                description:
                - "'v1'= IKEv1 key exchange; 'v2'= IKEv2 key exchange;"
            key_passphrase_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED key string)"
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
                - "'main'= Negotiate Main mode (Default); 'aggressive'= Negotiate Aggressive mode;"
            local_address:
                description:
                - "Field local_address"
            key:
                description:
                - "Private Key"
            preshare_key_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED pre-shared key string)"
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
                - "'1'= Diffie-Hellman group 1 - 768-bit(Default); '2'= Diffie-Hellman group 2 -
          1024-bit; '5'= Diffie-Hellman group 5 - 1536-bit; '14'= Diffie-Hellman group 14
          - 2048-bit; '15'= Diffie-Hellman group 15 - 3072-bit; '16'= Diffie-Hellman
          group 16 - 4096-bit; '18'= Diffie-Hellman group 18 - 8192-bit; '19'= Diffie-
          Hellman group 19 - 256-bit Elliptic Curve; '20'= Diffie-Hellman group 20 -
          384-bit Elliptic Curve;"
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
                - "'preshare-key'= Authenticate the remote gateway using a pre-shared key
          (Default); 'rsa-signature'= Authenticate the remote gateway using an RSA
          certificate; 'ecdsa-signature'= Authenticate the remote gateway using an ECDSA
          certificate;"
    fragment_after_encap:
        description:
        - "Fragment after adding IPsec headers"
        required: False
    ipsec_error_dump:
        description:
        - "Support record the error ipsec cavium information in dump file"
        required: False
    nat_traversal_flow_affinity:
        description:
        - "Choose IPsec UDP source port based on port of inner flow (only for A10 to A10)"
        required: False
    asymmetric_flow_support:
        description:
        - "Support asymmetric flows pass through IPsec tunnel"
        required: False
    ocsp:
        description:
        - "Field ocsp"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
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
    uuid:
        description:
        - "uuid of the object"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            ike_gateway_list:
                description:
                - "Field ike_gateway_list"
            ha_standby_drop:
                description:
                - "Field ha_standby_drop"
            error:
                description:
                - "Field error"
            passthrough:
                description:
                - "Field passthrough"
            ike_stats_global:
                description:
                - "Field ike_stats_global"
            ipsec_list:
                description:
                - "Field ipsec_list"
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
    default:
        description:
        - "Field default"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    crl:
        description:
        - "Field crl"
        required: False
        suboptions:
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'passthrough'= passthrough; 'ha-standby-drop'= ha-standby-drop;"
    errordump:
        description:
        - "Field errordump"
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
                - "'0'= Diffie-Hellman group 0 (Default); '1'= Diffie-Hellman group 1 - 768-bits;
          '2'= Diffie-Hellman group 2 - 1024-bits; '5'= Diffie-Hellman group 5 -
          1536-bits; '14'= Diffie-Hellman group 14 - 2048-bits; '15'= Diffie-Hellman
          group 15 - 3072-bits; '16'= Diffie-Hellman group 16 - 4096-bits; '18'= Diffie-
          Hellman group 18 - 8192-bits; '19'= Diffie-Hellman group 19 - 256-bit Elliptic
          Curve; '20'= Diffie-Hellman group 20 - 384-bit Elliptic Curve;"
            proto:
                description:
                - "'esp'= Encapsulating security protocol (Default);"
            up:
                description:
                - "Initiates SA negotiation to bring the IPsec connection up"
            user_tag:
                description:
                - "Customized tag"
            anti_replay_window:
                description:
                - "'0'= Disable Anti-Replay Window Check; '32'= Window size of 32; '64'= Window
          size of 64; '128'= Window size of 128; '256'= Window size of 256; '512'= Window
          size of 512; '1024'= Window size of 1024;"
            sampling_enable:
                description:
                - "Field sampling_enable"
            ike_gateway:
                description:
                - "Gateway to use for IPsec SA"
            mode:
                description:
                - "'tunnel'= Encapsulating the packet in IPsec tunnel mode (Default);"
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
    ipsec_sa_by_gw:
        description:
        - "Field ipsec_sa_by_gw"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    stateful_mode:
        description:
        - "VPN module will work in stateful mode and create sessions"
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
    "asymmetric_flow_support",
    "crl",
    "default",
    "error",
    "errordump",
    "fragment_after_encap",
    "ike_gateway_list",
    "ike_sa_timeout",
    "ike_stats_global",
    "ipsec_error_dump",
    "ipsec_list",
    "ipsec_sa_by_gw",
    "jumbo_fragment",
    "log",
    "nat_traversal_flow_affinity",
    "ocsp",
    "oper",
    "revocation_list",
    "sampling_enable",
    "stateful_mode",
    "stats",
    "tcp_mss_adjust_disable",
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
        'oper': {
            'type': 'dict',
            'ipsec_sa_by_gw': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'local_ip': {
                        'type': 'str',
                    },
                    'ike_gateway_name': {
                        'type': 'str',
                    },
                    'ipsec_sa_list': {
                        'type': 'list',
                        'lifebytes': {
                            'type': 'str',
                        },
                        'protocol': {
                            'type': 'str',
                        },
                        'remote_ts': {
                            'type': 'str',
                        },
                        'out_spi': {
                            'type': 'str',
                        },
                        'local_ts': {
                            'type': 'str',
                        },
                        'ipsec_sa_name': {
                            'type': 'str',
                        },
                        'in_spi': {
                            'type': 'str',
                        },
                        'mode': {
                            'type': 'str',
                        },
                        'encryption': {
                            'type': 'str',
                        },
                        'lifetime': {
                            'type': 'int',
                        },
                        'hash': {
                            'type': 'str',
                        }
                    },
                    'peer_ip': {
                        'type': 'str',
                    }
                }
            },
            'ipsec_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'Status': {
                        'type': 'str',
                    },
                    'Hash_Algorithm': {
                        'type': 'str',
                    },
                    'Protocol': {
                        'type': 'str',
                    },
                    'DH_Group': {
                        'type': 'int',
                    },
                    'Remote_SPI': {
                        'type': 'str',
                    },
                    'Local_IP': {
                        'type': 'str',
                    },
                    'Anti_Replay': {
                        'type': 'str',
                    },
                    'Lifebytes': {
                        'type': 'str',
                    },
                    'SA_Index': {
                        'type': 'int',
                    },
                    'Peer_IP': {
                        'type': 'str',
                    },
                    'Mode': {
                        'type': 'str',
                    },
                    'NAT_Traversal': {
                        'type': 'int',
                    },
                    'Local_SPI': {
                        'type': 'str',
                    },
                    'Encryption_Algorithm': {
                        'type': 'str',
                    },
                    'Lifetime': {
                        'type': 'int',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'all_partitions': {
                'type': 'bool',
            },
            'Num_hardware_devices': {
                'type': 'int',
            },
            'IPsec_mode': {
                'type': 'str',
            },
            'specific_partition': {
                'type': 'str',
            },
            'IKE_Gateway_total': {
                'type': 'int',
            },
            'ike_gateway_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'Status': {
                        'type': 'str',
                    },
                    'Remote_IP': {
                        'type': 'str',
                    },
                    'Hash': {
                        'type': 'str',
                    },
                    'NAT_Traversal': {
                        'type': 'int',
                    },
                    'Local_IP': {
                        'type': 'str',
                    },
                    'Responder_SPI': {
                        'type': 'str',
                    },
                    'Encryption': {
                        'type': 'str',
                    },
                    'Lifetime': {
                        'type': 'int',
                    },
                    'Initiator_SPI': {
                        'type': 'str',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'all_partition_list': {
                'type': 'list',
                'standby_drop': {
                    'type': 'int',
                },
                'IPsec_mode': {
                    'type': 'str',
                },
                'IKE_Gateway_total': {
                    'type': 'int',
                },
                'Crypto_hw_err_req_alloc_fail': {
                    'type': 'int',
                },
                'Crypto_mem': {
                    'type': 'int',
                },
                'Crypto_hw_err_req_error': {
                    'type': 'int',
                },
                'IPsec_SA_total': {
                    'type': 'int',
                },
                'IPsec_stateless': {
                    'type': 'int',
                },
                'Crypto_cores_total': {
                    'type': 'int',
                },
                'IPsec_total': {
                    'type': 'int',
                },
                'Crypto_hw_err_bad_pointer': {
                    'type': 'int',
                },
                'Crypto_hw_err_bad_ctx_pointer': {
                    'type': 'int',
                },
                'Crypto_hw_err_enqueue_fail': {
                    'type': 'int',
                },
                'Crypto_hw_err_time_out_state': {
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
                'Num_hardware_devices': {
                    'type': 'int',
                },
                'Crypto_hw_err_state': {
                    'type': 'str',
                },
                'Crypto_cores_assigned_to_IPsec': {
                    'type': 'int',
                },
                'IKE_SA_total': {
                    'type': 'int',
                },
                'Crypto_hw_err': {
                    'type': 'int',
                },
                'passthrough_total': {
                    'type': 'int',
                },
                'Crypto_hw_err_sg_buff_alloc_fail': {
                    'type': 'int',
                },
                'Crypto_hw_err_buff_alloc_error': {
                    'type': 'int',
                },
                'partition_name': {
                    'type': 'str',
                },
                'Crypto_hw_err_state_error': {
                    'type': 'int',
                },
                'Crypto_hw_err_time_out': {
                    'type': 'int',
                }
            },
            'IPsec_SA_total': {
                'type': 'int',
            },
            'default': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'ike_local_address': {
                        'type': 'str',
                    },
                    'ike_version': {
                        'type': 'str',
                    },
                    'IPsec_remote_subnet': {
                        'type': 'str',
                    },
                    'IPsec_mode': {
                        'type': 'str',
                    },
                    'ike_nat_traversal': {
                        'type': 'str',
                    },
                    'ike_dpd_interval': {
                        'type': 'int',
                    },
                    'IPsec_priority': {
                        'type': 'int',
                    },
                    'IPsec_traffic_selector': {
                        'type': 'str',
                    },
                    'ike_encryption': {
                        'type': 'str',
                    },
                    'IPsec_remote_port': {
                        'type': 'int',
                    },
                    'IPsec_hash': {
                        'type': 'str',
                    },
                    'IPsec_protocol': {
                        'type': 'str',
                    },
                    'ike_priority': {
                        'type': 'int',
                    },
                    'ike_hash': {
                        'type': 'str',
                    },
                    'IPsec_remote_protocol': {
                        'type': 'int',
                    },
                    'ike_remote_address': {
                        'type': 'str',
                    },
                    'ike_dh_group': {
                        'type': 'str',
                    },
                    'ike_auth_method': {
                        'type': 'str',
                    },
                    'IPsec_anti_replay_window': {
                        'type': 'int',
                    },
                    'ike_lifetime': {
                        'type': 'int',
                    },
                    'IPsec_lifetime': {
                        'type': 'int',
                    },
                    'IPsec_local_protocol': {
                        'type': 'int',
                    },
                    'IPsec_local_port': {
                        'type': 'int',
                    },
                    'IPsec_lifebytes': {
                        'type': 'int',
                    },
                    'IPsec_encryption': {
                        'type': 'str',
                    },
                    'IPsec_local_subnet': {
                        'type': 'str',
                    },
                    'IPsec_dh_group': {
                        'type': 'str',
                    },
                    'ike_mode': {
                        'type': 'str',
                    }
                }
            },
            'Crypto_cores_assigned_to_IPsec': {
                'type': 'int',
            },
            'IKE_SA_total': {
                'type': 'int',
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
            'Crypto_cores_total': {
                'type': 'int',
            },
            'IPsec_total': {
                'type': 'int',
            },
            'shared': {
                'type': 'bool',
            },
            'ocsp': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'total_ocsps': {
                        'type': 'int',
                    },
                    'ocsp_list': {
                        'type': 'list',
                        'certificate_status': {
                            'type': 'str',
                        },
                        'subject': {
                            'type': 'str',
                        },
                        'validity': {
                            'type': 'str',
                        },
                        'issuer': {
                            'type': 'str',
                        }
                    }
                }
            },
            'Crypto_mem': {
                'type': 'int',
            },
            'crl': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'total_crls': {
                        'type': 'int',
                    },
                    'crl_list': {
                        'type': 'list',
                        'revoked': {
                            'type': 'str',
                        },
                        'storage_type': {
                            'type': 'str',
                        },
                        'updates': {
                            'type': 'str',
                        },
                        'serial': {
                            'type': 'str',
                        },
                        'subject': {
                            'type': 'str',
                        },
                        'issuer': {
                            'type': 'str',
                        }
                    }
                }
            },
            'log': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'vpn_log_offset': {
                        'type': 'int',
                    },
                    'vpn_log_over': {
                        'type': 'int',
                    },
                    'vpn_log_list': {
                        'type': 'list',
                        'vpn_log_data': {
                            'type': 'str',
                        }
                    },
                    'from_start': {
                        'type': 'bool',
                    },
                    'follow': {
                        'type': 'bool',
                    },
                    'num_lines': {
                        'type': 'int',
                    }
                }
            }
        },
        'tcp_mss_adjust_disable': {
            'type': 'bool',
        },
        'ike_gateway_list': {
            'type': 'list',
            'ike_version': {
                'type': 'str',
                'choices': ['v1', 'v2']
            },
            'key_passphrase_encrypted': {
                'type': 'str',
            },
            'local_cert': {
                'type': 'dict',
                'local_cert_name': {
                    'type': 'str',
                }
            },
            'lifetime': {
                'type': 'int',
            },
            'local_id': {
                'type': 'str',
            },
            'enc_cfg': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'encryption': {
                    'type':
                    'str',
                    'choices':
                    ['des', '3des', 'aes-128', 'aes-192', 'aes-256', 'null']
                },
                'hash': {
                    'type': 'str',
                    'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
                }
            },
            'uuid': {
                'type': 'str',
            },
            'nat_traversal': {
                'type': 'bool',
            },
            'vrid': {
                'type': 'dict',
                'vrid_num': {
                    'type': 'int',
                }
            },
            'preshare_key_value': {
                'type': 'str',
            },
            'key_passphrase': {
                'type': 'str',
            },
            'mode': {
                'type': 'str',
                'choices': ['main', 'aggressive']
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
            'key': {
                'type': 'str',
            },
            'preshare_key_encrypted': {
                'type': 'str',
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
            'remote_ca_cert': {
                'type': 'dict',
                'remote_cert_name': {
                    'type': 'str',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'dh_group': {
                'type': 'str',
                'choices': ['1', '2', '5', '14', '15', '16', '18', '19', '20']
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
                        'all', 'v2-init-rekey', 'v2-rsp-rekey',
                        'v2-child-sa-rekey', 'v2-in-invalid',
                        'v2-in-invalid-spi', 'v2-in-init-req',
                        'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp',
                        'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req',
                        'v2-out-auth-rsp', 'v2-in-create-child-req',
                        'v2-in-create-child-rsp', 'v2-out-create-child-req',
                        'v2-out-create-child-rsp', 'v2-in-info-req',
                        'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp',
                        'v1-in-id-prot-req', 'v1-in-id-prot-rsp',
                        'v1-out-id-prot-req', 'v1-out-id-prot-rsp',
                        'v1-in-auth-only-req', 'v1-in-auth-only-rsp',
                        'v1-out-auth-only-req', 'v1-out-auth-only-rsp',
                        'v1-in-aggressive-req', 'v1-in-aggressive-rsp',
                        'v1-out-aggressive-req', 'v1-out-aggressive-rsp',
                        'v1-in-info-v1-req', 'v1-in-info-v1-rsp',
                        'v1-out-info-v1-req', 'v1-out-info-v1-rsp',
                        'v1-in-transaction-req', 'v1-in-transaction-rsp',
                        'v1-out-transaction-req', 'v1-out-transaction-rsp',
                        'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp',
                        'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp',
                        'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp',
                        'v1-out-new-group-mode-req',
                        'v1-out-new-group-mode-rsp', 'v1-child-sa-invalid-spi',
                        'v2-child-sa-invalid-spi', 'ike-current-version'
                    ]
                }
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
            'remote_id': {
                'type': 'str',
            },
            'auth_method': {
                'type': 'str',
                'choices':
                ['preshare-key', 'rsa-signature', 'ecdsa-signature']
            }
        },
        'fragment_after_encap': {
            'type': 'bool',
        },
        'ipsec_error_dump': {
            'type': 'bool',
        },
        'nat_traversal_flow_affinity': {
            'type': 'bool',
        },
        'asymmetric_flow_support': {
            'type': 'bool',
        },
        'ocsp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'ike_stats_global': {
            'type': 'dict',
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'v2-init-rekey', 'v2-rsp-rekey',
                        'v2-child-sa-rekey', 'v2-in-invalid',
                        'v2-in-invalid-spi', 'v2-in-init-req',
                        'v2-in-init-rsp', 'v2-out-init-req', 'v2-out-init-rsp',
                        'v2-in-auth-req', 'v2-in-auth-rsp', 'v2-out-auth-req',
                        'v2-out-auth-rsp', 'v2-in-create-child-req',
                        'v2-in-create-child-rsp', 'v2-out-create-child-req',
                        'v2-out-create-child-rsp', 'v2-in-info-req',
                        'v2-in-info-rsp', 'v2-out-info-req', 'v2-out-info-rsp',
                        'v1-in-id-prot-req', 'v1-in-id-prot-rsp',
                        'v1-out-id-prot-req', 'v1-out-id-prot-rsp',
                        'v1-in-auth-only-req', 'v1-in-auth-only-rsp',
                        'v1-out-auth-only-req', 'v1-out-auth-only-rsp',
                        'v1-in-aggressive-req', 'v1-in-aggressive-rsp',
                        'v1-out-aggressive-req', 'v1-out-aggressive-rsp',
                        'v1-in-info-v1-req', 'v1-in-info-v1-rsp',
                        'v1-out-info-v1-req', 'v1-out-info-v1-rsp',
                        'v1-in-transaction-req', 'v1-in-transaction-rsp',
                        'v1-out-transaction-req', 'v1-out-transaction-rsp',
                        'v1-in-quick-mode-req', 'v1-in-quick-mode-rsp',
                        'v1-out-quick-mode-req', 'v1-out-quick-mode-rsp',
                        'v1-in-new-group-mode-req', 'v1-in-new-group-mode-rsp',
                        'v1-out-new-group-mode-req',
                        'v1-out-new-group-mode-rsp'
                    ]
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'ike_gateway_list': {
                'type': 'list',
                'stats': {
                    'type': 'dict',
                    'v1_in_id_prot_rsp': {
                        'type': 'str',
                    },
                    'v1_in_auth_only_rsp': {
                        'type': 'str',
                    },
                    'v1_out_quick_mode_req': {
                        'type': 'str',
                    },
                    'v1_out_aggressive_req': {
                        'type': 'str',
                    },
                    'v2_child_sa_rekey': {
                        'type': 'str',
                    },
                    'ike_current_version': {
                        'type': 'str',
                    },
                    'v2_out_auth_req': {
                        'type': 'str',
                    },
                    'v2_rsp_rekey': {
                        'type': 'str',
                    },
                    'v2_out_info_req': {
                        'type': 'str',
                    },
                    'v2_out_init_req': {
                        'type': 'str',
                    },
                    'v1_in_info_v1_rsp': {
                        'type': 'str',
                    },
                    'v1_out_id_prot_req': {
                        'type': 'str',
                    },
                    'v2_in_invalid': {
                        'type': 'str',
                    },
                    'v1_in_aggressive_req': {
                        'type': 'str',
                    },
                    'v1_child_sa_invalid_spi': {
                        'type': 'str',
                    },
                    'v2_in_info_rsp': {
                        'type': 'str',
                    },
                    'v1_out_new_group_mode_rsp': {
                        'type': 'str',
                    },
                    'v2_out_auth_rsp': {
                        'type': 'str',
                    },
                    'v1_in_auth_only_req': {
                        'type': 'str',
                    },
                    'v1_in_info_v1_req': {
                        'type': 'str',
                    },
                    'v2_in_create_child_req': {
                        'type': 'str',
                    },
                    'v2_out_info_rsp': {
                        'type': 'str',
                    },
                    'v2_out_create_child_req': {
                        'type': 'str',
                    },
                    'v2_in_auth_rsp': {
                        'type': 'str',
                    },
                    'v2_in_init_req': {
                        'type': 'str',
                    },
                    'v1_out_info_v1_req': {
                        'type': 'str',
                    },
                    'v2_init_rekey': {
                        'type': 'str',
                    },
                    'v1_in_id_prot_req': {
                        'type': 'str',
                    },
                    'v1_out_transaction_rsp': {
                        'type': 'str',
                    },
                    'v1_out_quick_mode_rsp': {
                        'type': 'str',
                    },
                    'v1_out_auth_only_rsp': {
                        'type': 'str',
                    },
                    'v1_in_quick_mode_rsp': {
                        'type': 'str',
                    },
                    'v1_in_new_group_mode_req': {
                        'type': 'str',
                    },
                    'v1_out_id_prot_rsp': {
                        'type': 'str',
                    },
                    'v1_in_transaction_rsp': {
                        'type': 'str',
                    },
                    'v1_in_aggressive_rsp': {
                        'type': 'str',
                    },
                    'v1_in_transaction_req': {
                        'type': 'str',
                    },
                    'v1_in_quick_mode_req': {
                        'type': 'str',
                    },
                    'v2_in_invalid_spi': {
                        'type': 'str',
                    },
                    'v1_out_auth_only_req': {
                        'type': 'str',
                    },
                    'v1_out_transaction_req': {
                        'type': 'str',
                    },
                    'v1_out_new_group_mode_req': {
                        'type': 'str',
                    },
                    'v2_child_sa_invalid_spi': {
                        'type': 'str',
                    },
                    'v1_out_info_v1_rsp': {
                        'type': 'str',
                    },
                    'v2_in_init_rsp': {
                        'type': 'str',
                    },
                    'v2_in_create_child_rsp': {
                        'type': 'str',
                    },
                    'v2_in_auth_req': {
                        'type': 'str',
                    },
                    'v2_out_init_rsp': {
                        'type': 'str',
                    },
                    'v1_in_new_group_mode_rsp': {
                        'type': 'str',
                    },
                    'v2_out_create_child_rsp': {
                        'type': 'str',
                    },
                    'v1_out_aggressive_rsp': {
                        'type': 'str',
                    },
                    'v2_in_info_req': {
                        'type': 'str',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
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
                    'ipv6_rh_length_error': {
                        'type': 'str',
                    },
                    'ah_not_supported_with_gcm_gmac_sha2': {
                        'type': 'str',
                    },
                    'bad_auth_type': {
                        'type': 'str',
                    },
                    'bad_gre_protocol': {
                        'type': 'str',
                    },
                    'ipv6_outbound_rh_copy_addr_error': {
                        'type': 'str',
                    },
                    'bad_ip_payload_type': {
                        'type': 'str',
                    },
                    'ipv6_extension_headers_too_big': {
                        'type': 'str',
                    },
                    'bad_encrypt_type': {
                        'type': 'str',
                    },
                    'bad_checksum': {
                        'type': 'str',
                    },
                    'bad_gre_header': {
                        'type': 'str',
                    },
                    'bad_ipsec_context': {
                        'type': 'str',
                    },
                    'bad_min_frag_size_auth_sha384_512': {
                        'type': 'str',
                    },
                    'bad_ipsec_padding': {
                        'type': 'str',
                    },
                    'bad_inline_data': {
                        'type': 'str',
                    },
                    'dummy_payload': {
                        'type': 'str',
                    },
                    'bad_ip_version': {
                        'type': 'str',
                    },
                    'bad_encrypt_type_ctr_gcm': {
                        'type': 'str',
                    },
                    'bad_fragment_size': {
                        'type': 'str',
                    },
                    'bad_esp_next_header': {
                        'type': 'str',
                    },
                    'ipv6_hop_by_hop_error': {
                        'type': 'str',
                    },
                    'error_ipv6_decrypt_rh_segs_left_error': {
                        'type': 'str',
                    },
                    'bad_ipsec_spi': {
                        'type': 'str',
                    },
                    'bad_ipsec_context_flag_mismatch': {
                        'type': 'str',
                    },
                    'error_IPv6_extension_header_bad': {
                        'type': 'str',
                    },
                    'bad_ipsec_protocol': {
                        'type': 'str',
                    },
                    'bad_frag_size_configuration': {
                        'type': 'str',
                    },
                    'bad_ipsec_auth': {
                        'type': 'str',
                    },
                    'bad_ipcomp_configuration': {
                        'type': 'str',
                    },
                    'bad_len': {
                        'type': 'str',
                    },
                    'bad_ipsec_context_direction': {
                        'type': 'str',
                    },
                    'bad_ipsec_unknown': {
                        'type': 'str',
                    },
                    'ipcomp_payload': {
                        'type': 'str',
                    },
                    'bad_srtp_auth_tag': {
                        'type': 'str',
                    },
                    'tfc_padding_with_prefrag_not_supported': {
                        'type': 'str',
                    },
                    'dsiv_incorrect_param': {
                        'type': 'str',
                    },
                    'bad_selector_match': {
                        'type': 'str',
                    }
                }
            },
            'passthrough': {
                'type': 'str',
            },
            'ike_stats_global': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'v1_in_id_prot_rsp': {
                        'type': 'str',
                    },
                    'v1_in_auth_only_rsp': {
                        'type': 'str',
                    },
                    'v1_out_quick_mode_req': {
                        'type': 'str',
                    },
                    'v1_out_aggressive_req': {
                        'type': 'str',
                    },
                    'v2_child_sa_rekey': {
                        'type': 'str',
                    },
                    'v2_out_auth_req': {
                        'type': 'str',
                    },
                    'v2_rsp_rekey': {
                        'type': 'str',
                    },
                    'v2_out_info_req': {
                        'type': 'str',
                    },
                    'v2_out_init_req': {
                        'type': 'str',
                    },
                    'v1_in_info_v1_rsp': {
                        'type': 'str',
                    },
                    'v1_out_id_prot_req': {
                        'type': 'str',
                    },
                    'v2_in_invalid': {
                        'type': 'str',
                    },
                    'v1_in_aggressive_req': {
                        'type': 'str',
                    },
                    'v2_in_info_rsp': {
                        'type': 'str',
                    },
                    'v1_out_new_group_mode_rsp': {
                        'type': 'str',
                    },
                    'v2_out_auth_rsp': {
                        'type': 'str',
                    },
                    'v1_in_auth_only_req': {
                        'type': 'str',
                    },
                    'v1_in_info_v1_req': {
                        'type': 'str',
                    },
                    'v2_in_create_child_req': {
                        'type': 'str',
                    },
                    'v2_out_info_rsp': {
                        'type': 'str',
                    },
                    'v2_out_create_child_req': {
                        'type': 'str',
                    },
                    'v2_in_auth_rsp': {
                        'type': 'str',
                    },
                    'v2_in_init_req': {
                        'type': 'str',
                    },
                    'v1_out_info_v1_req': {
                        'type': 'str',
                    },
                    'v2_init_rekey': {
                        'type': 'str',
                    },
                    'v1_in_id_prot_req': {
                        'type': 'str',
                    },
                    'v1_out_transaction_rsp': {
                        'type': 'str',
                    },
                    'v1_out_quick_mode_rsp': {
                        'type': 'str',
                    },
                    'v1_out_auth_only_rsp': {
                        'type': 'str',
                    },
                    'v1_in_quick_mode_rsp': {
                        'type': 'str',
                    },
                    'v1_in_new_group_mode_req': {
                        'type': 'str',
                    },
                    'v1_out_id_prot_rsp': {
                        'type': 'str',
                    },
                    'v1_in_transaction_rsp': {
                        'type': 'str',
                    },
                    'v1_in_aggressive_rsp': {
                        'type': 'str',
                    },
                    'v1_in_transaction_req': {
                        'type': 'str',
                    },
                    'v1_in_quick_mode_req': {
                        'type': 'str',
                    },
                    'v2_in_invalid_spi': {
                        'type': 'str',
                    },
                    'v1_out_auth_only_req': {
                        'type': 'str',
                    },
                    'v1_out_transaction_req': {
                        'type': 'str',
                    },
                    'v1_out_new_group_mode_req': {
                        'type': 'str',
                    },
                    'v1_out_info_v1_rsp': {
                        'type': 'str',
                    },
                    'v2_in_init_rsp': {
                        'type': 'str',
                    },
                    'v2_in_create_child_rsp': {
                        'type': 'str',
                    },
                    'v2_in_auth_req': {
                        'type': 'str',
                    },
                    'v2_out_init_rsp': {
                        'type': 'str',
                    },
                    'v1_in_new_group_mode_rsp': {
                        'type': 'str',
                    },
                    'v2_out_create_child_rsp': {
                        'type': 'str',
                    },
                    'v1_out_aggressive_rsp': {
                        'type': 'str',
                    },
                    'v2_in_info_req': {
                        'type': 'str',
                    }
                }
            },
            'ipsec_list': {
                'type': 'list',
                'stats': {
                    'type': 'dict',
                    'anti_replay_num': {
                        'type': 'str',
                    },
                    'packets_decrypted': {
                        'type': 'str',
                    },
                    'tunnel_intf_down': {
                        'type': 'str',
                    },
                    'pkt_fail_to_send': {
                        'type': 'str',
                    },
                    'packets_encrypted': {
                        'type': 'str',
                    },
                    'bytes_encrypted': {
                        'type': 'str',
                    },
                    'packets_err_nh_check': {
                        'type': 'str',
                    },
                    'no_tunnel_found': {
                        'type': 'str',
                    },
                    'cavium_packets_decrypted': {
                        'type': 'str',
                    },
                    'prefrag_error': {
                        'type': 'str',
                    },
                    'bytes_decrypted': {
                        'type': 'str',
                    },
                    'invalid_tunnel_id': {
                        'type': 'str',
                    },
                    'pkt_fail_prep_to_send': {
                        'type': 'str',
                    },
                    'cavium_packets_encrypted': {
                        'type': 'str',
                    },
                    'packets_err_icv_check': {
                        'type': 'str',
                    },
                    'packets_err_inactive': {
                        'type': 'str',
                    },
                    'cavium_bytes_decrypted': {
                        'type': 'str',
                    },
                    'sequence_num_rollover': {
                        'type': 'str',
                    },
                    'packets_err_pkt_sanity': {
                        'type': 'str',
                    },
                    'frag_after_encap_frag_packets': {
                        'type': 'str',
                    },
                    'cavium_bytes_encrypted': {
                        'type': 'str',
                    },
                    'sequence_num': {
                        'type': 'str',
                    },
                    'packets_err_lifetime_lifebytes': {
                        'type': 'str',
                    },
                    'packets_err_encryption': {
                        'type': 'str',
                    },
                    'rekey_num': {
                        'type': 'str',
                    },
                    'prefrag_success': {
                        'type': 'str',
                    },
                    'packets_err_pad_check': {
                        'type': 'str',
                    },
                    'no_next_hop': {
                        'type': 'str',
                    },
                    'frag_received': {
                        'type': 'str',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            }
        },
        'jumbo_fragment': {
            'type': 'bool',
        },
        'log': {
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
        'crl': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
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
            'user_tag': {
                'type': 'str',
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
            'crl': {
                'type': 'dict',
                'crl_sec': {
                    'type': 'str',
                },
                'crl_pri': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type': 'str',
                'choices': ['all', 'passthrough', 'ha-standby-drop']
            }
        },
        'errordump': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'ike_sa_timeout': {
            'type': 'int',
        },
        'error': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'ipsec_list': {
            'type': 'list',
            'uuid': {
                'type': 'str',
            },
            'lifebytes': {
                'type': 'int',
            },
            'bind_tunnel': {
                'type': 'dict',
                'tunnel': {
                    'type': 'int',
                },
                'next_hop': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'next_hop_v6': {
                    'type': 'str',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'dh_group': {
                'type': 'str',
                'choices':
                ['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']
            },
            'proto': {
                'type': 'str',
                'choices': ['esp']
            },
            'up': {
                'type': 'bool',
            },
            'user_tag': {
                'type': 'str',
            },
            'anti_replay_window': {
                'type': 'str',
                'choices': ['0', '32', '64', '128', '256', '512', '1024']
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
                        'tunnel-intf-down', 'pkt-fail-prep-to-send',
                        'no-next-hop', 'invalid-tunnel-id', 'no-tunnel-found',
                        'pkt-fail-to-send', 'frag-after-encap-frag-packets',
                        'frag-received', 'sequence-num',
                        'sequence-num-rollover', 'packets-err-nh-check'
                    ]
                }
            },
            'ike_gateway': {
                'type': 'str',
            },
            'mode': {
                'type': 'str',
                'choices': ['tunnel']
            },
            'sequence_number_disable': {
                'type': 'bool',
            },
            'lifetime': {
                'type': 'int',
            },
            'enc_cfg': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'encryption': {
                    'type':
                    'str',
                    'choices': [
                        'des', '3des', 'aes-128', 'aes-192', 'aes-256',
                        'aes-gcm-128', 'aes-gcm-192', 'aes-gcm-256', 'null'
                    ]
                },
                'gcm_priority': {
                    'type': 'int',
                },
                'hash': {
                    'type':
                    'str',
                    'choices':
                    ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'null']
                }
            },
            'traffic_selector': {
                'type': 'dict',
                'ipv4': {
                    'type': 'dict',
                    'remote': {
                        'type': 'str',
                    },
                    'local_port': {
                        'type': 'int',
                    },
                    'remote_port': {
                        'type': 'int',
                    },
                    'local_netmask': {
                        'type': 'str',
                    },
                    'remote_netmask': {
                        'type': 'str',
                    },
                    'protocol': {
                        'type': 'int',
                    },
                    'local': {
                        'type': 'str',
                    }
                },
                'ipv6': {
                    'type': 'dict',
                    'local_portv6': {
                        'type': 'int',
                    },
                    'protocolv6': {
                        'type': 'int',
                    },
                    'localv6': {
                        'type': 'str',
                    },
                    'remotev6': {
                        'type': 'str',
                    },
                    'remote_portv6': {
                        'type': 'int',
                    }
                }
            }
        },
        'ipsec_sa_by_gw': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'stateful_mode': {
            'type': 'bool',
        }
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
    url_base = "/axapi/v3/vpn"

    f_dict = {}

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
        for k, v in payload["vpn"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["vpn"][k] != v:
                    if result["changed"] is not True:
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
