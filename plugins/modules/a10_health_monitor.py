#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_health_monitor
description:
    - Define the Health Monitor object
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
        - "Monitor Name"
        type: str
        required: True
    dsr_l2_strict:
        description:
        - "Enable strict L2dsr health-check"
        type: bool
        required: False
    retry:
        description:
        - "Specify the Healthcheck Retries (Retry Count (default 3))"
        type: int
        required: False
    up_retry:
        description:
        - "Specify the Healthcheck Retries before declaring target up (Up-retry count
          (default 1))"
        type: int
        required: False
    override_ipv4:
        description:
        - "Override implicitly inherited IPv4 address from target"
        type: str
        required: False
    override_ipv6:
        description:
        - "Override implicitly inherited IPv6 address from target"
        type: str
        required: False
    override_port:
        description:
        - "Override implicitly inherited port from target (Port number (1-65534))"
        type: int
        required: False
    passive:
        description:
        - "Specify passive mode"
        type: bool
        required: False
    status_code:
        description:
        - "'status-code-2xx'= Enable passive mode with 2xx http status code; 'status-code-
          non-5xx'= Enable passive mode with non-5xx http status code;"
        type: str
        required: False
    passive_interval:
        description:
        - "Interval to do manual health checking while in passive mode (Specify value in
          seconds (Default is 10 s))"
        type: int
        required: False
    sample_threshold:
        description:
        - "Number of samples in one epoch above which passive HC is enabled. If below or
          equal to the threshold, passive HC is disabled (Specify number of samples in
          one second (Default is 50). If the number of samples is 0, no action is taken)"
        type: int
        required: False
    threshold:
        description:
        - "Threshold percentage above which passive mode is enabled (Specify percentage
          (Default is 75%))"
        type: int
        required: False
    strict_retry_on_server_err_resp:
        description:
        - "Require strictly retry"
        type: bool
        required: False
    disable_after_down:
        description:
        - "Disable the target if health check failed"
        type: bool
        required: False
    interval:
        description:
        - "Specify the Healthcheck Interval (Interval Value, in seconds (default 5))"
        type: int
        required: False
    timeout:
        description:
        - "Specify the Healthcheck Timeout (Timeout Value, in seconds(default 5), Timeout
          should be less than or equal to interval)"
        type: int
        required: False
    ssl_ciphers:
        description:
        - "Specify OpenSSL Cipher Suite name(s) for Health check (OpenSSL Cipher Suite(s)
          (Eg= AES128-SHA256), if the cipher is invalid, would give information at HM
          down reason)"
        type: str
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
    method:
        description:
        - "Field method"
        type: dict
        required: False
        suboptions:
            icmp:
                description:
                - "Field icmp"
                type: dict
            tcp:
                description:
                - "Field tcp"
                type: dict
            udp:
                description:
                - "Field udp"
                type: dict
            http:
                description:
                - "Field http"
                type: dict
            ftp:
                description:
                - "Field ftp"
                type: dict
            snmp:
                description:
                - "Field snmp"
                type: dict
            smtp:
                description:
                - "Field smtp"
                type: dict
            dns:
                description:
                - "Field dns"
                type: dict
            pop3:
                description:
                - "Field pop3"
                type: dict
            imap:
                description:
                - "Field imap"
                type: dict
            sip:
                description:
                - "Field sip"
                type: dict
            radius:
                description:
                - "Field radius"
                type: dict
            ldap:
                description:
                - "Field ldap"
                type: dict
            rtsp:
                description:
                - "Field rtsp"
                type: dict
            database:
                description:
                - "Field database"
                type: dict
            external:
                description:
                - "Field external"
                type: dict
            ntp:
                description:
                - "Field ntp"
                type: dict
            kerberos_kdc:
                description:
                - "Field kerberos_kdc"
                type: dict
            https:
                description:
                - "Field https"
                type: dict
            tacplus:
                description:
                - "Field tacplus"
                type: dict
            compound:
                description:
                - "Field compound"
                type: dict

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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

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
            type='str',
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
        'dsr_l2_strict': {
            'type': 'bool',
        },
        'retry': {
            'type': 'int',
        },
        'up_retry': {
            'type': 'int',
        },
        'override_ipv4': {
            'type': 'str',
        },
        'override_ipv6': {
            'type': 'str',
        },
        'override_port': {
            'type': 'int',
        },
        'passive': {
            'type': 'bool',
        },
        'status_code': {
            'type': 'str',
            'choices': ['status-code-2xx', 'status-code-non-5xx']
        },
        'passive_interval': {
            'type': 'int',
        },
        'sample_threshold': {
            'type': 'int',
        },
        'threshold': {
            'type': 'int',
        },
        'strict_retry_on_server_err_resp': {
            'type': 'bool',
        },
        'disable_after_down': {
            'type': 'bool',
        },
        'interval': {
            'type': 'int',
        },
        'timeout': {
            'type': 'int',
        },
        'ssl_ciphers': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'method': {
            'type': 'dict',
            'icmp': {
                'type': 'dict',
                'icmp': {
                    'type': 'bool',
                },
                'transparent': {
                    'type': 'bool',
                },
                'ipv6': {
                    'type': 'str',
                },
                'ip': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'tcp': {
                'type': 'dict',
                'method_tcp': {
                    'type': 'bool',
                },
                'tcp_port': {
                    'type': 'int',
                },
                'port_halfopen': {
                    'type': 'bool',
                },
                'port_send': {
                    'type': 'str',
                },
                'port_resp': {
                    'type': 'dict',
                    'port_contains': {
                        'type': 'str',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'udp': {
                'type': 'dict',
                'udp': {
                    'type': 'bool',
                },
                'udp_port': {
                    'type': 'int',
                },
                'force_up_with_single_healthcheck': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'http': {
                'type': 'dict',
                'http': {
                    'type': 'bool',
                },
                'http_port': {
                    'type': 'int',
                },
                'http_expect': {
                    'type': 'bool',
                },
                'http_response_code': {
                    'type': 'str',
                },
                'response_code_regex': {
                    'type': 'str',
                },
                'http_text': {
                    'type': 'str',
                },
                'text_regex': {
                    'type': 'str',
                },
                'http_host': {
                    'type': 'str',
                },
                'http_maintenance_code': {
                    'type': 'str',
                },
                'http_url': {
                    'type': 'bool',
                },
                'url_type': {
                    'type': 'str',
                    'choices': ['GET', 'POST', 'HEAD']
                },
                'url_path': {
                    'type': 'str',
                },
                'post_path': {
                    'type': 'str',
                },
                'post_type': {
                    'type': 'str',
                    'choices': ['postdata', 'postfile']
                },
                'http_postdata': {
                    'type': 'str',
                },
                'http_postfile': {
                    'type': 'str',
                },
                'http_username': {
                    'type': 'str',
                },
                'http_password': {
                    'type': 'bool',
                },
                'http_password_string': {
                    'type': 'str',
                },
                'http_encrypted': {
                    'type': 'str',
                },
                'http_kerberos_auth': {
                    'type': 'bool',
                },
                'http_kerberos_realm': {
                    'type': 'str',
                },
                'http_kerberos_kdc': {
                    'type': 'dict',
                    'http_kerberos_hostip': {
                        'type': 'str',
                    },
                    'http_kerberos_hostipv6': {
                        'type': 'str',
                    },
                    'http_kerberos_port': {
                        'type': 'int',
                    },
                    'http_kerberos_portv6': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ftp': {
                'type': 'dict',
                'ftp': {
                    'type': 'bool',
                },
                'ftp_port': {
                    'type': 'int',
                },
                'ftp_username': {
                    'type': 'str',
                },
                'ftp_password': {
                    'type': 'bool',
                },
                'ftp_password_string': {
                    'type': 'str',
                },
                'ftp_encrypted': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'snmp': {
                'type': 'dict',
                'snmp': {
                    'type': 'bool',
                },
                'snmp_port': {
                    'type': 'int',
                },
                'community': {
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
                'operation': {
                    'type': 'dict',
                    'oper_type': {
                        'type': 'str',
                        'choices': ['getnext', 'get']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'smtp': {
                'type': 'dict',
                'smtp': {
                    'type': 'bool',
                },
                'smtp_domain': {
                    'type': 'str',
                },
                'smtp_port': {
                    'type': 'int',
                },
                'smtp_starttls': {
                    'type': 'bool',
                },
                'mail_from': {
                    'type': 'str',
                },
                'rcpt_to': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'dns': {
                'type': 'dict',
                'dns': {
                    'type': 'bool',
                },
                'dns_ip_key': {
                    'type': 'bool',
                },
                'dns_ipv4_addr': {
                    'type': 'str',
                },
                'dns_ipv6_addr': {
                    'type': 'str',
                },
                'dns_ipv4_port': {
                    'type': 'int',
                },
                'dns_ipv4_expect': {
                    'type': 'dict',
                    'dns_ipv4_response': {
                        'type': 'str',
                    }
                },
                'dns_ipv4_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'dns_ipv4_tcp': {
                    'type': 'bool',
                },
                'dns_ipv6_port': {
                    'type': 'int',
                },
                'dns_ipv6_expect': {
                    'type': 'dict',
                    'dns_ipv6_response': {
                        'type': 'str',
                    }
                },
                'dns_ipv6_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'dns_ipv6_tcp': {
                    'type': 'bool',
                },
                'dns_domain': {
                    'type': 'str',
                },
                'dns_domain_port': {
                    'type': 'int',
                },
                'dns_domain_expect': {
                    'type': 'dict',
                    'dns_domain_response': {
                        'type': 'str',
                    }
                },
                'dns_domain_recurse': {
                    'type': 'str',
                    'choices': ['enabled', 'disabled']
                },
                'dns_domain_tcp': {
                    'type': 'bool',
                },
                'dns_domain_type': {
                    'type': 'str',
                    'choices':
                    ['A', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'AAAA']
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'pop3': {
                'type': 'dict',
                'pop3': {
                    'type': 'bool',
                },
                'pop3_username': {
                    'type': 'str',
                },
                'pop3_password': {
                    'type': 'bool',
                },
                'pop3_password_string': {
                    'type': 'str',
                },
                'pop3_encrypted': {
                    'type': 'str',
                },
                'pop3_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'imap': {
                'type': 'dict',
                'imap': {
                    'type': 'bool',
                },
                'imap_port': {
                    'type': 'int',
                },
                'imap_username': {
                    'type': 'str',
                },
                'imap_password': {
                    'type': 'bool',
                },
                'imap_password_string': {
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
                'imap_cram_md5': {
                    'type': 'bool',
                },
                'imap_login': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'sip': {
                'type': 'dict',
                'sip': {
                    'type': 'bool',
                },
                'register': {
                    'type': 'bool',
                },
                'sip_port': {
                    'type': 'int',
                },
                'expect_response_code': {
                    'type': 'str',
                },
                'sip_tcp': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'radius': {
                'type': 'dict',
                'radius': {
                    'type': 'bool',
                },
                'radius_username': {
                    'type': 'str',
                },
                'radius_password': {
                    'type': 'bool',
                },
                'radius_password_string': {
                    'type': 'str',
                },
                'radius_encrypted': {
                    'type': 'str',
                },
                'radius_secret': {
                    'type': 'str',
                },
                'radius_port': {
                    'type': 'int',
                },
                'radius_expect': {
                    'type': 'bool',
                },
                'radius_response_code': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ldap': {
                'type': 'dict',
                'ldap': {
                    'type': 'bool',
                },
                'ldap_port': {
                    'type': 'int',
                },
                'ldap_security': {
                    'type': 'str',
                    'choices': ['overssl', 'StartTLS']
                },
                'ldap_binddn': {
                    'type': 'str',
                },
                'ldap_password': {
                    'type': 'bool',
                },
                'ldap_password_string': {
                    'type': 'str',
                },
                'ldap_encrypted': {
                    'type': 'str',
                },
                'ldap_run_search': {
                    'type': 'bool',
                },
                'BaseDN': {
                    'type': 'str',
                },
                'ldap_query': {
                    'type': 'str',
                },
                'AcceptResRef': {
                    'type': 'bool',
                },
                'AcceptNotFound': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'rtsp': {
                'type': 'dict',
                'rtsp': {
                    'type': 'bool',
                },
                'rtspurl': {
                    'type': 'str',
                },
                'rtsp_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'database': {
                'type': 'dict',
                'database': {
                    'type': 'bool',
                },
                'database_name': {
                    'type': 'str',
                    'choices': ['mssql', 'mysql', 'oracle', 'postgresql']
                },
                'db_name': {
                    'type': 'str',
                },
                'db_username': {
                    'type': 'str',
                },
                'db_password': {
                    'type': 'bool',
                },
                'db_password_str': {
                    'type': 'str',
                },
                'db_encrypted': {
                    'type': 'str',
                },
                'db_send': {
                    'type': 'str',
                },
                'db_receive': {
                    'type': 'str',
                },
                'db_row': {
                    'type': 'int',
                },
                'db_column': {
                    'type': 'int',
                },
                'db_receive_integer': {
                    'type': 'int',
                },
                'db_row_integer': {
                    'type': 'int',
                },
                'db_column_integer': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'external': {
                'type': 'dict',
                'external': {
                    'type': 'bool',
                },
                'ext_program': {
                    'type': 'str',
                },
                'shared_partition_program': {
                    'type': 'bool',
                },
                'ext_program_shared': {
                    'type': 'str',
                },
                'ext_port': {
                    'type': 'int',
                },
                'ext_arguments': {
                    'type': 'str',
                },
                'ext_preference': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ntp': {
                'type': 'dict',
                'ntp': {
                    'type': 'bool',
                },
                'ntp_port': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'kerberos_kdc': {
                'type': 'dict',
                'kerberos_cfg': {
                    'type': 'dict',
                    'kinit': {
                        'type': 'bool',
                    },
                    'kinit_pricipal_name': {
                        'type': 'str',
                    },
                    'kinit_password': {
                        'type': 'str',
                    },
                    'kinit_encrypted': {
                        'type': 'str',
                    },
                    'kinit_kdc': {
                        'type': 'str',
                    },
                    'tcp_only': {
                        'type': 'bool',
                    },
                    'kadmin': {
                        'type': 'bool',
                    },
                    'kadmin_realm': {
                        'type': 'str',
                    },
                    'kadmin_pricipal_name': {
                        'type': 'str',
                    },
                    'kadmin_password': {
                        'type': 'str',
                    },
                    'kadmin_encrypted': {
                        'type': 'str',
                    },
                    'kadmin_server': {
                        'type': 'str',
                    },
                    'kadmin_kdc': {
                        'type': 'str',
                    },
                    'kpasswd': {
                        'type': 'bool',
                    },
                    'kpasswd_pricipal_name': {
                        'type': 'str',
                    },
                    'kpasswd_password': {
                        'type': 'str',
                    },
                    'kpasswd_encrypted': {
                        'type': 'str',
                    },
                    'kpasswd_server': {
                        'type': 'str',
                    },
                    'kpasswd_kdc': {
                        'type': 'str',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'https': {
                'type': 'dict',
                'https': {
                    'type': 'bool',
                },
                'web_port': {
                    'type': 'int',
                },
                'https_expect': {
                    'type': 'bool',
                },
                'https_response_code': {
                    'type': 'str',
                },
                'response_code_regex': {
                    'type': 'str',
                },
                'https_text': {
                    'type': 'str',
                },
                'text_regex': {
                    'type': 'str',
                },
                'https_host': {
                    'type': 'str',
                },
                'https_maintenance_code': {
                    'type': 'str',
                },
                'https_url': {
                    'type': 'bool',
                },
                'url_type': {
                    'type': 'str',
                    'choices': ['GET', 'POST', 'HEAD']
                },
                'url_path': {
                    'type': 'str',
                },
                'post_path': {
                    'type': 'str',
                },
                'post_type': {
                    'type': 'str',
                    'choices': ['postdata', 'postfile']
                },
                'https_postdata': {
                    'type': 'str',
                },
                'https_postfile': {
                    'type': 'str',
                },
                'https_username': {
                    'type': 'str',
                },
                'https_password': {
                    'type': 'bool',
                },
                'https_password_string': {
                    'type': 'str',
                },
                'https_encrypted': {
                    'type': 'str',
                },
                'disable_sslv2hello': {
                    'type': 'bool',
                },
                'https_kerberos_auth': {
                    'type': 'bool',
                },
                'https_kerberos_realm': {
                    'type': 'str',
                },
                'https_kerberos_kdc': {
                    'type': 'dict',
                    'https_kerberos_hostip': {
                        'type': 'str',
                    },
                    'https_kerberos_hostipv6': {
                        'type': 'str',
                    },
                    'https_kerberos_port': {
                        'type': 'int',
                    },
                    'https_kerberos_portv6': {
                        'type': 'int',
                    }
                },
                'cert_key_shared': {
                    'type': 'bool',
                },
                'cert': {
                    'type': 'str',
                },
                'key': {
                    'type': 'str',
                },
                'key_pass_phrase': {
                    'type': 'bool',
                },
                'key_phrase': {
                    'type': 'str',
                },
                'https_key_encrypted': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'tacplus': {
                'type': 'dict',
                'tacplus': {
                    'type': 'bool',
                },
                'tacplus_username': {
                    'type': 'str',
                },
                'tacplus_password': {
                    'type': 'bool',
                },
                'tacplus_password_string': {
                    'type': 'str',
                },
                'tacplus_encrypted': {
                    'type': 'str',
                },
                'tacplus_secret': {
                    'type': 'bool',
                },
                'tacplus_secret_string': {
                    'type': 'str',
                },
                'secret_encrypted': {
                    'type': 'str',
                },
                'tacplus_port': {
                    'type': 'int',
                },
                'tacplus_type': {
                    'type': 'str',
                    'choices': ['inbound-ascii-login']
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'compound': {
                'type': 'dict',
                'compound': {
                    'type': 'bool',
                },
                'rpn_string': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            }
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


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/health/monitor/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["monitor"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["monitor"].get(k) != v:
            change_results["changed"] = True
            config_changes["monitor"][k] = v

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
    payload = utils.build_json("monitor", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
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
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
