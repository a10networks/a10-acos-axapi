#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_health_monitor
description:
    - Define the Health Monitor object
short_description: Configures A10 health.monitor
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
    override_ipv4:
        description:
        - "Override implicitly inherited IPv4 address from target"
        required: False
    override_ipv6:
        description:
        - "Override implicitly inherited IPv6 address from target"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    ssl_ciphers:
        description:
        - "Specify OpenSSL Cipher Suite name(s) for Health check (OpenSSL Cipher Suite(s)
          (Eg= AES128-SHA256), if the cipher is invalid, would give information at HM
          down reason)"
        required: False
    strict_retry_on_server_err_resp:
        description:
        - "Require strictly retry"
        required: False
    passive_interval:
        description:
        - "Interval to do manual health checking while in passive mode (Specify value in
          seconds (Default is 10 s))"
        required: False
    override_port:
        description:
        - "Override implicitly inherited port from target (Port number (1-65534))"
        required: False
    up_retry:
        description:
        - "Specify the Healthcheck Retries before declaring target up (Up-retry count
          (default 1))"
        required: False
    interval:
        description:
        - "Specify the Healthcheck Interval (Interval Value, in seconds (default 5))"
        required: False
    sample_threshold:
        description:
        - "Number of samples in one epoch above which passive HC is enabled. If below or
          equal to the threshold, passive HC is disabled (Specify number of samples in
          one second (Default is 50). If the number of samples is 0, no action is taken)"
        required: False
    retry:
        description:
        - "Specify the Healthcheck Retries (Retry Count (default 3))"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    timeout:
        description:
        - "Specify the Healthcheck Timeout (Timeout Value, in seconds(default 5), Timeout
          should be less than or equal to interval)"
        required: False
    passive:
        description:
        - "Specify passive mode"
        required: False
    threshold:
        description:
        - "Threshold percentage above which passive mode is enabled (Specify percentage
          (Default is 75%))"
        required: False
    dsr_l2_strict:
        description:
        - "Enable strict L2dsr health-check"
        required: False
    status_code:
        description:
        - "'status-code-2xx'= Enable passive mode with 2xx http status code; 'status-code-
          non-5xx'= Enable passive mode with non-5xx http status code;"
        required: False
    disable_after_down:
        description:
        - "Disable the target if health check failed"
        required: False
    method:
        description:
        - "Field method"
        required: False
        suboptions:
            ftp:
                description:
                - "Field ftp"
            udp:
                description:
                - "Field udp"
            sip:
                description:
                - "Field sip"
            http:
                description:
                - "Field http"
            dns:
                description:
                - "Field dns"
            database:
                description:
                - "Field database"
            ntp:
                description:
                - "Field ntp"
            icmp:
                description:
                - "Field icmp"
            rtsp:
                description:
                - "Field rtsp"
            smtp:
                description:
                - "Field smtp"
            tcp:
                description:
                - "Field tcp"
            pop3:
                description:
                - "Field pop3"
            tacplus:
                description:
                - "Field tacplus"
            radius:
                description:
                - "Field radius"
            external:
                description:
                - "Field external"
            https:
                description:
                - "Field https"
            compound:
                description:
                - "Field compound"
            ldap:
                description:
                - "Field ldap"
            snmp:
                description:
                - "Field snmp"
            kerberos_kdc:
                description:
                - "Field kerberos_kdc"
            imap:
                description:
                - "Field imap"
    name:
        description:
        - "Monitor Name"
        required: True

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
    "disable_after_down",
    "dsr_l2_strict",
    "interval",
    "method",
    "name",
    "override_ipv4",
    "override_ipv6",
    "override_port",
    "passive",
    "passive_interval",
    "retry",
    "sample_threshold",
    "ssl_ciphers",
    "status_code",
    "strict_retry_on_server_err_resp",
    "threshold",
    "timeout",
    "up_retry",
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
        'override_ipv4': {
            'type': 'str',
        },
        'override_ipv6': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'ssl_ciphers': {
            'type': 'str',
        },
        'strict_retry_on_server_err_resp': {
            'type': 'bool',
        },
        'passive_interval': {
            'type': 'int',
        },
        'override_port': {
            'type': 'int',
        },
        'up_retry': {
            'type': 'int',
        },
        'interval': {
            'type': 'int',
        },
        'sample_threshold': {
            'type': 'int',
        },
        'retry': {
            'type': 'int',
        },
        'user_tag': {
            'type': 'str',
        },
        'timeout': {
            'type': 'int',
        },
        'passive': {
            'type': 'bool',
        },
        'threshold': {
            'type': 'int',
        },
        'dsr_l2_strict': {
            'type': 'bool',
        },
        'status_code': {
            'type': 'str',
            'choices': ['status-code-2xx', 'status-code-non-5xx']
        },
        'disable_after_down': {
            'type': 'bool',
        },
        'method': {
            'type': 'dict',
            'ftp': {
                'type': 'dict',
                'ftp': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'ftp_password_string': {
                    'type': 'str',
                },
                'ftp_password': {
                    'type': 'bool',
                },
                'ftp_port': {
                    'type': 'int',
                },
                'ftp_encrypted': {
                    'type': 'str',
                },
                'ftp_username': {
                    'type': 'str',
                }
            },
            'udp': {
                'type': 'dict',
                'udp': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'force_up_with_single_healthcheck': {
                    'type': 'bool',
                },
                'udp_port': {
                    'type': 'int',
                }
            },
            'sip': {
                'type': 'dict',
                'sip': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'register': {
                    'type': 'bool',
                },
                'expect_response_code': {
                    'type': 'str',
                },
                'sip_port': {
                    'type': 'int',
                },
                'sip_tcp': {
                    'type': 'bool',
                }
            },
            'http': {
                'type': 'dict',
                'http_url': {
                    'type': 'bool',
                },
                'text_regex': {
                    'type': 'str',
                },
                'http_maintenance_code': {
                    'type': 'str',
                },
                'http_kerberos_auth': {
                    'type': 'bool',
                },
                'http_postfile': {
                    'type': 'str',
                },
                'response_code_regex': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'post_type': {
                    'type': 'str',
                    'choices': ['postdata', 'postfile']
                },
                'http_password_string': {
                    'type': 'str',
                },
                'url_path': {
                    'type': 'str',
                },
                'http_response_code': {
                    'type': 'str',
                },
                'http_host': {
                    'type': 'str',
                },
                'http': {
                    'type': 'bool',
                },
                'url_type': {
                    'type': 'str',
                    'choices': ['GET', 'POST', 'HEAD']
                },
                'http_postdata': {
                    'type': 'str',
                },
                'http_text': {
                    'type': 'str',
                },
                'http_encrypted': {
                    'type': 'str',
                },
                'http_kerberos_realm': {
                    'type': 'str',
                },
                'http_password': {
                    'type': 'bool',
                },
                'http_kerberos_kdc': {
                    'type': 'dict',
                    'http_kerberos_hostipv6': {
                        'type': 'str',
                    },
                    'http_kerberos_port': {
                        'type': 'int',
                    },
                    'http_kerberos_portv6': {
                        'type': 'int',
                    },
                    'http_kerberos_hostip': {
                        'type': 'str',
                    }
                },
                'http_expect': {
                    'type': 'bool',
                },
                'post_path': {
                    'type': 'str',
                },
                'http_username': {
                    'type': 'str',
                },
                'http_port': {
                    'type': 'int',
                }
            },
            'dns': {
                'type': 'dict',
                'dns_domain_type': {
                    'type': 'str',
                    'choices':
                    ['A', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'AAAA']
                },
                'dns_ipv4_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'uuid': {
                    'type': 'str',
                },
                'dns_ipv6_port': {
                    'type': 'int',
                },
                'dns_ipv4_addr': {
                    'type': 'str',
                },
                'dns_domain_expect': {
                    'type': 'dict',
                    'dns_domain_response': {
                        'type': 'str',
                    }
                },
                'dns_ipv4_expect': {
                    'type': 'dict',
                    'dns_ipv4_response': {
                        'type': 'str',
                    }
                },
                'dns_ipv4_port': {
                    'type': 'int',
                },
                'dns_ipv6_expect': {
                    'type': 'dict',
                    'dns_ipv6_response': {
                        'type': 'str',
                    }
                },
                'dns_ip_key': {
                    'type': 'bool',
                },
                'dns_ipv6_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'dns_ipv6_tcp': {
                    'type': 'bool',
                },
                'dns_domain_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'dns_domain_tcp': {
                    'type': 'bool',
                },
                'dns': {
                    'type': 'bool',
                },
                'dns_ipv4_tcp': {
                    'type': 'bool',
                },
                'dns_domain': {
                    'type': 'str',
                },
                'dns_ipv6_addr': {
                    'type': 'str',
                },
                'dns_domain_port': {
                    'type': 'int',
                }
            },
            'database': {
                'type': 'dict',
                'db_send': {
                    'type': 'str',
                },
                'db_password': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'db_encrypted': {
                    'type': 'str',
                },
                'database': {
                    'type': 'bool',
                },
                'database_name': {
                    'type': 'str',
                    'choices': ['mssql', 'mysql', 'oracle', 'postgresql']
                },
                'db_row_integer': {
                    'type': 'int',
                },
                'db_receive': {
                    'type': 'str',
                },
                'db_receive_integer': {
                    'type': 'int',
                },
                'db_password_str': {
                    'type': 'str',
                },
                'db_column': {
                    'type': 'int',
                },
                'db_name': {
                    'type': 'str',
                },
                'db_column_integer': {
                    'type': 'int',
                },
                'db_username': {
                    'type': 'str',
                },
                'db_row': {
                    'type': 'int',
                }
            },
            'ntp': {
                'type': 'dict',
                'ntp': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'ntp_port': {
                    'type': 'int',
                }
            },
            'icmp': {
                'type': 'dict',
                'ip': {
                    'type': 'str',
                },
                'icmp': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'ipv6': {
                    'type': 'str',
                },
                'transparent': {
                    'type': 'bool',
                }
            },
            'rtsp': {
                'type': 'dict',
                'rtsp_port': {
                    'type': 'int',
                },
                'rtsp': {
                    'type': 'bool',
                },
                'rtspurl': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'smtp': {
                'type': 'dict',
                'smtp_port': {
                    'type': 'int',
                },
                'smtp_starttls': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'smtp_domain': {
                    'type': 'str',
                },
                'smtp': {
                    'type': 'bool',
                },
                'mail_from': {
                    'type': 'str',
                },
                'rcpt_to': {
                    'type': 'str',
                }
            },
            'tcp': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                },
                'tcp_port': {
                    'type': 'int',
                },
                'port_resp': {
                    'type': 'dict',
                    'port_contains': {
                        'type': 'str',
                    }
                },
                'method_tcp': {
                    'type': 'bool',
                },
                'port_send': {
                    'type': 'str',
                },
                'port_halfopen': {
                    'type': 'bool',
                }
            },
            'pop3': {
                'type': 'dict',
                'pop3_password_string': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'pop3_password': {
                    'type': 'bool',
                },
                'pop3_username': {
                    'type': 'str',
                },
                'pop3_encrypted': {
                    'type': 'str',
                },
                'pop3': {
                    'type': 'bool',
                },
                'pop3_port': {
                    'type': 'int',
                }
            },
            'tacplus': {
                'type': 'dict',
                'tacplus_encrypted': {
                    'type': 'str',
                },
                'secret_encrypted': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'tacplus_password_string': {
                    'type': 'str',
                },
                'tacplus_secret': {
                    'type': 'bool',
                },
                'tacplus_username': {
                    'type': 'str',
                },
                'tacplus': {
                    'type': 'bool',
                },
                'tacplus_secret_string': {
                    'type': 'str',
                },
                'tacplus_type': {
                    'type': 'str',
                    'choices': ['inbound-ascii-login']
                },
                'tacplus_password': {
                    'type': 'bool',
                },
                'tacplus_port': {
                    'type': 'int',
                }
            },
            'radius': {
                'type': 'dict',
                'radius_username': {
                    'type': 'str',
                },
                'radius_password_string': {
                    'type': 'str',
                },
                'radius_encrypted': {
                    'type': 'str',
                },
                'radius_response_code': {
                    'type': 'str',
                },
                'radius_expect': {
                    'type': 'bool',
                },
                'radius': {
                    'type': 'bool',
                },
                'radius_secret': {
                    'type': 'str',
                },
                'radius_password': {
                    'type': 'bool',
                },
                'radius_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'external': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                },
                'external': {
                    'type': 'bool',
                },
                'ext_preference': {
                    'type': 'bool',
                },
                'ext_arguments': {
                    'type': 'str',
                },
                'shared_partition_program': {
                    'type': 'bool',
                },
                'ext_port': {
                    'type': 'int',
                },
                'ext_program_shared': {
                    'type': 'str',
                },
                'ext_program': {
                    'type': 'str',
                }
            },
            'https': {
                'type': 'dict',
                'https_kerberos_realm': {
                    'type': 'str',
                },
                'cert_key_shared': {
                    'type': 'bool',
                },
                'response_code_regex': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'post_type': {
                    'type': 'str',
                    'choices': ['postdata', 'postfile']
                },
                'https_kerberos_auth': {
                    'type': 'bool',
                },
                'https_username': {
                    'type': 'str',
                },
                'key_phrase': {
                    'type': 'str',
                },
                'https_postdata': {
                    'type': 'str',
                },
                'https_key_encrypted': {
                    'type': 'str',
                },
                'https_expect': {
                    'type': 'bool',
                },
                'https': {
                    'type': 'bool',
                },
                'text_regex': {
                    'type': 'str',
                },
                'https_host': {
                    'type': 'str',
                },
                'key_pass_phrase': {
                    'type': 'bool',
                },
                'https_encrypted': {
                    'type': 'str',
                },
                'url_type': {
                    'type': 'str',
                    'choices': ['GET', 'POST', 'HEAD']
                },
                'web_port': {
                    'type': 'int',
                },
                'disable_sslv2hello': {
                    'type': 'bool',
                },
                'https_kerberos_kdc': {
                    'type': 'dict',
                    'https_kerberos_hostip': {
                        'type': 'str',
                    },
                    'https_kerberos_port': {
                        'type': 'int',
                    },
                    'https_kerberos_portv6': {
                        'type': 'int',
                    },
                    'https_kerberos_hostipv6': {
                        'type': 'str',
                    }
                },
                'key': {
                    'type': 'str',
                },
                'https_password_string': {
                    'type': 'str',
                },
                'post_path': {
                    'type': 'str',
                },
                'https_postfile': {
                    'type': 'str',
                },
                'https_password': {
                    'type': 'bool',
                },
                'cert': {
                    'type': 'str',
                },
                'https_text': {
                    'type': 'str',
                },
                'https_response_code': {
                    'type': 'str',
                },
                'url_path': {
                    'type': 'str',
                },
                'https_maintenance_code': {
                    'type': 'str',
                },
                'https_url': {
                    'type': 'bool',
                }
            },
            'compound': {
                'type': 'dict',
                'rpn_string': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'compound': {
                    'type': 'bool',
                }
            },
            'ldap': {
                'type': 'dict',
                'AcceptResRef': {
                    'type': 'bool',
                },
                'ldap_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'ldap_password_string': {
                    'type': 'str',
                },
                'ldap_encrypted': {
                    'type': 'str',
                },
                'BaseDN': {
                    'type': 'str',
                },
                'ldap_password': {
                    'type': 'bool',
                },
                'ldap_binddn': {
                    'type': 'str',
                },
                'ldap_query': {
                    'type': 'str',
                },
                'ldap_security': {
                    'type': 'str',
                    'choices': ['overssl', 'StartTLS']
                },
                'ldap': {
                    'type': 'bool',
                },
                'ldap_run_search': {
                    'type': 'bool',
                },
                'AcceptNotFound': {
                    'type': 'bool',
                }
            },
            'snmp': {
                'type': 'dict',
                'snmp_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'oid': {
                    'type': 'dict',
                    'mib': {
                        'type': 'str',
                        'choices': ['sysDescr', 'sysUpTime', 'sysName']
                    },
                    'asn': {
                        'type': 'str',
                    }
                },
                'snmp': {
                    'type': 'bool',
                },
                'community': {
                    'type': 'str',
                },
                'operation': {
                    'type': 'dict',
                    'oper_type': {
                        'type': 'str',
                        'choices': ['getnext', 'get']
                    }
                }
            },
            'kerberos_kdc': {
                'type': 'dict',
                'kerberos_cfg': {
                    'type': 'dict',
                    'tcp_only': {
                        'type': 'bool',
                    },
                    'kpasswd_password': {
                        'type': 'str',
                    },
                    'kadmin_server': {
                        'type': 'str',
                    },
                    'kinit_password': {
                        'type': 'str',
                    },
                    'kpasswd': {
                        'type': 'bool',
                    },
                    'kinit_pricipal_name': {
                        'type': 'str',
                    },
                    'kpasswd_server': {
                        'type': 'str',
                    },
                    'kadmin_encrypted': {
                        'type': 'str',
                    },
                    'kinit': {
                        'type': 'bool',
                    },
                    'kadmin_pricipal_name': {
                        'type': 'str',
                    },
                    'kadmin_realm': {
                        'type': 'str',
                    },
                    'kinit_kdc': {
                        'type': 'str',
                    },
                    'kpasswd_pricipal_name': {
                        'type': 'str',
                    },
                    'kadmin': {
                        'type': 'bool',
                    },
                    'kadmin_kdc': {
                        'type': 'str',
                    },
                    'kpasswd_kdc': {
                        'type': 'str',
                    },
                    'kadmin_password': {
                        'type': 'str',
                    },
                    'kpasswd_encrypted': {
                        'type': 'str',
                    },
                    'kinit_encrypted': {
                        'type': 'str',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'imap': {
                'type': 'dict',
                'imap_cram_md5': {
                    'type': 'bool',
                },
                'imap_port': {
                    'type': 'int',
                },
                'imap_login': {
                    'type': 'bool',
                },
                'imap_password': {
                    'type': 'bool',
                },
                'imap_password_string': {
                    'type': 'str',
                },
                'imap_username': {
                    'type': 'str',
                },
                'imap_encrypted': {
                    'type': 'str',
                },
                'pwd_auth': {
                    'type': 'bool',
                },
                'imap_plain': {
                    'type': 'bool',
                },
                'imap': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{name}"

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
    url_base = "/axapi/v3/health/monitor/{name}"

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
        for k, v in payload["monitor"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["monitor"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["monitor"][k] = v
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
    payload = build_json("monitor", module)
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
