#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_site
description:
    - Specify a GSLB site
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
    site_name:
        description:
        - "Specify GSLB site name"
        type: str
        required: True
    auto_map:
        description:
        - "Enable DNS Auto Mapping"
        type: bool
        required: False
    disable:
        description:
        - "Disable all servers in the GSLB site"
        type: bool
        required: False
    weight:
        description:
        - "Specify a weight for the GSLB site (Weight, default is 1)"
        type: int
        required: False
    multiple_geo_locations:
        description:
        - "Field multiple_geo_locations"
        type: list
        required: False
        suboptions:
            geo_location:
                description:
                - "Specify the geographic location of the GSLB site (Specify geo-location for this
          site)"
                type: str
    template:
        description:
        - "Specify template to collect site information (Specify GSLB SNMP template name)"
        type: str
        required: False
    bw_cost:
        description:
        - "Specify cost of band-width"
        type: bool
        required: False
    limit:
        description:
        - "Specify the limit for bandwidth, default is unlimited"
        type: int
        required: False
    threshold:
        description:
        - "Specify the threshold for limit"
        type: int
        required: False
    proto_aging_time:
        description:
        - "Specify GSLB Protocol aging time"
        type: int
        required: False
    proto_aging_fast:
        description:
        - "Fast GSLB Protocol aging"
        type: bool
        required: False
    controller:
        description:
        - "Specify the local controller for the GSLB site (Specify the hostname of the
          local controller)"
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
    ip_server_list:
        description:
        - "Field ip_server_list"
        type: list
        required: False
        suboptions:
            ip_server_name:
                description:
                - "Specify the real server name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    active_rdt:
        description:
        - "Field active_rdt"
        type: dict
        required: False
        suboptions:
            aging_time:
                description:
                - "Aging Time, Unit= min, default is 10"
                type: int
            smooth_factor:
                description:
                - "Factor of Smooth RDT, default is 10"
                type: int
            range_factor:
                description:
                - "Factor of RDT Range, default is 25 (Range Factor of Smooth RDT)"
                type: int
            limit:
                description:
                - "Limit of valid RDT, default is 16383 (Limit, unit= millisecond)"
                type: int
            mask:
                description:
                - "Client IP subnet mask, default is 32"
                type: str
            ipv6_mask:
                description:
                - "Client IPv6 subnet mask, default is 128"
                type: int
            ignore_count:
                description:
                - "Ignore count if RDT is out of range, default is 5"
                type: int
            bind_geoloc:
                description:
                - "Bind RDT to geo-location"
                type: bool
            overlap:
                description:
                - "Enable overlap for geo-location to do longest match"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    easy_rdt:
        description:
        - "Field easy_rdt"
        type: dict
        required: False
        suboptions:
            aging_time:
                description:
                - "Aging Time, Unit= min, default is 10"
                type: int
            smooth_factor:
                description:
                - "Factor of Smooth RDT, default is 10"
                type: int
            range_factor:
                description:
                - "Factor of RDT Range, default is 25 (Range Factor of Smooth RDT)"
                type: int
            limit:
                description:
                - "Limit of valid RDT, default is 16383 (Limit, unit= millisecond)"
                type: int
            mask:
                description:
                - "Client IP subnet mask, default is 32"
                type: str
            ipv6_mask:
                description:
                - "Client IPv6 subnet mask, default is 128"
                type: int
            ignore_count:
                description:
                - "Ignore count if RDT is out of range, default is 5"
                type: int
            bind_geoloc:
                description:
                - "Bind RDT to geo-location"
                type: bool
            overlap:
                description:
                - "Enable overlap for geo-location to do longest match"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    slb_dev_list:
        description:
        - "Field slb_dev_list"
        type: list
        required: False
        suboptions:
            device_name:
                description:
                - "Specify SLB device name"
                type: str
            ip_address:
                description:
                - "IP address"
                type: str
            ipv6_address:
                description:
                - "IPv6 address"
                type: str
            domain:
                description:
                - "Device hostname"
                type: str
            dev_resolve_as:
                description:
                - "'resolve-to-ipv4'= Use A Query only to resolve FQDN (Default Query type);
          'resolve-to-ipv6'= Use AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-
          ipv6'= Use A as well as AAAA Query to resolve FQDN;"
                type: str
            admin_preference:
                description:
                - "Specify administrative preference (Specify admin-preference value,default is
          100)"
                type: int
            session_number:
                description:
                - "Field session_number"
                type: int
            session_utilization:
                description:
                - "Field session_utilization"
                type: int
            rdt_type:
                description:
                - "'rdt'= rdt; 'site-rdt'= site-rdt;"
                type: str
            client_ip:
                description:
                - "Specify client IP address"
                type: str
            rdt_value:
                description:
                - "Specify Round-delay-time"
                type: int
            probe_timer:
                description:
                - "Field probe_timer"
                type: int
            auto_detect:
                description:
                - "'ip'= Service IP only; 'port'= Service Port only; 'ip-and-port'= Both service
          IP and service port; 'disabled'= disable auto-detect;"
                type: str
            auto_map:
                description:
                - "Enable DNS Auto Mapping"
                type: bool
            max_client:
                description:
                - "Specify maximum number of clients, default is 32768"
                type: int
            proto_aging_time:
                description:
                - "Specify GSLB Protocol aging time, default is 60"
                type: int
            proto_aging_fast:
                description:
                - "Fast GSLB Protocol aging"
                type: bool
            health_check_action:
                description:
                - "'health-check'= Enable health Check; 'health-check-disable'= Disable health
          check;"
                type: str
            gateway_ip_addr:
                description:
                - "IP address"
                type: str
            proto_compatible:
                description:
                - "Run GSLB Protocol in compatible mode"
                type: bool
            msg_format_acos_2x:
                description:
                - "Run GSLB Protocol in compatible mode with a ACOS 2.x GSLB peer"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            vip_server:
                description:
                - "Field vip_server"
                type: dict
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            gslb_site:
                description:
                - "Field gslb_site"
                type: str
            state:
                description:
                - "Field state"
                type: str
            type_last:
                description:
                - "Field type_last"
                type: list
            client_ldns_list:
                description:
                - "Field client_ldns_list"
                type: list
            site_name:
                description:
                - "Specify GSLB site name"
                type: str
            ip_server_list:
                description:
                - "Field ip_server_list"
                type: list
            slb_dev_list:
                description:
                - "Field slb_dev_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hits:
                description:
                - "Number of times the site was selected"
                type: str
            site_name:
                description:
                - "Specify GSLB site name"
                type: str
            ip_server_list:
                description:
                - "Field ip_server_list"
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
AVAILABLE_PROPERTIES = ["active_rdt", "auto_map", "bw_cost", "controller", "disable", "easy_rdt", "ip_server_list", "limit", "multiple_geo_locations", "oper", "proto_aging_fast", "proto_aging_time", "site_name", "slb_dev_list", "stats", "template", "threshold", "user_tag", "uuid", "weight", ]


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
        'site_name': {
            'type': 'str',
            'required': True,
            },
        'auto_map': {
            'type': 'bool',
            },
        'disable': {
            'type': 'bool',
            },
        'weight': {
            'type': 'int',
            },
        'multiple_geo_locations': {
            'type': 'list',
            'geo_location': {
                'type': 'str',
                }
            },
        'template': {
            'type': 'str',
            },
        'bw_cost': {
            'type': 'bool',
            },
        'limit': {
            'type': 'int',
            },
        'threshold': {
            'type': 'int',
            },
        'proto_aging_time': {
            'type': 'int',
            },
        'proto_aging_fast': {
            'type': 'bool',
            },
        'controller': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'ip_server_list': {
            'type': 'list',
            'ip_server_name': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                }
            },
        'active_rdt': {
            'type': 'dict',
            'aging_time': {
                'type': 'int',
                },
            'smooth_factor': {
                'type': 'int',
                },
            'range_factor': {
                'type': 'int',
                },
            'limit': {
                'type': 'int',
                },
            'mask': {
                'type': 'str',
                },
            'ipv6_mask': {
                'type': 'int',
                },
            'ignore_count': {
                'type': 'int',
                },
            'bind_geoloc': {
                'type': 'bool',
                },
            'overlap': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'easy_rdt': {
            'type': 'dict',
            'aging_time': {
                'type': 'int',
                },
            'smooth_factor': {
                'type': 'int',
                },
            'range_factor': {
                'type': 'int',
                },
            'limit': {
                'type': 'int',
                },
            'mask': {
                'type': 'str',
                },
            'ipv6_mask': {
                'type': 'int',
                },
            'ignore_count': {
                'type': 'int',
                },
            'bind_geoloc': {
                'type': 'bool',
                },
            'overlap': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'slb_dev_list': {
            'type': 'list',
            'device_name': {
                'type': 'str',
                'required': True,
                },
            'ip_address': {
                'type': 'str',
                },
            'ipv6_address': {
                'type': 'str',
                },
            'domain': {
                'type': 'str',
                },
            'dev_resolve_as': {
                'type': 'str',
                'choices': ['resolve-to-ipv4', 'resolve-to-ipv6', 'resolve-to-ipv4-and-ipv6']
                },
            'admin_preference': {
                'type': 'int',
                },
            'session_number': {
                'type': 'int',
                },
            'session_utilization': {
                'type': 'int',
                },
            'rdt_type': {
                'type': 'str',
                'choices': ['rdt', 'site-rdt']
                },
            'client_ip': {
                'type': 'str',
                },
            'rdt_value': {
                'type': 'int',
                },
            'probe_timer': {
                'type': 'int',
                },
            'auto_detect': {
                'type': 'str',
                'choices': ['ip', 'port', 'ip-and-port', 'disabled']
                },
            'auto_map': {
                'type': 'bool',
                },
            'max_client': {
                'type': 'int',
                },
            'proto_aging_time': {
                'type': 'int',
                },
            'proto_aging_fast': {
                'type': 'bool',
                },
            'health_check_action': {
                'type': 'str',
                'choices': ['health-check', 'health-check-disable']
                },
            'gateway_ip_addr': {
                'type': 'str',
                },
            'proto_compatible': {
                'type': 'bool',
                },
            'msg_format_acos_2x': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'vip_server': {
                'type': 'dict',
                'vip_server_v4_list': {
                    'type': 'list',
                    'ipv4': {
                        'type': 'str',
                        'required': True,
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'dev_vip_hits', 'dev_vip_recent']
                            }
                        }
                    },
                'vip_server_v6_list': {
                    'type': 'list',
                    'ipv6': {
                        'type': 'str',
                        'required': True,
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'dev_vip_hits', 'dev_vip_recent']
                            }
                        }
                    },
                'vip_server_name_list': {
                    'type': 'list',
                    'vip_name': {
                        'type': 'str',
                        'required': True,
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'dev_vip_hits', 'dev_vip_recent']
                            }
                        }
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'gslb_site': {
                'type': 'str',
                },
            'state': {
                'type': 'str',
                },
            'type_last': {
                'type': 'list',
                'ntype': {
                    'type': 'str',
                    },
                'last': {
                    'type': 'str',
                    }
                },
            'client_ldns_list': {
                'type': 'list',
                'client_ip': {
                    'type': 'str',
                    },
                'age': {
                    'type': 'int',
                    },
                'ntype': {
                    'type': 'str',
                    },
                'rdt_sample1': {
                    'type': 'int',
                    },
                'rdt_sample2': {
                    'type': 'int',
                    },
                'rdt_sample3': {
                    'type': 'int',
                    },
                'rdt_sample4': {
                    'type': 'int',
                    },
                'rdt_sample5': {
                    'type': 'int',
                    },
                'rdt_sample6': {
                    'type': 'int',
                    },
                'rdt_sample7': {
                    'type': 'int',
                    },
                'rdt_sample8': {
                    'type': 'int',
                    }
                },
            'site_name': {
                'type': 'str',
                'required': True,
                },
            'ip_server_list': {
                'type': 'list',
                'ip_server_name': {
                    'type': 'str',
                    'required': True,
                    },
                'oper': {
                    'type': 'dict',
                    'ip_server': {
                        'type': 'str',
                        },
                    'ip_address': {
                        'type': 'str',
                        },
                    'state': {
                        'type': 'str',
                        },
                    'service_ip': {
                        'type': 'str',
                        },
                    'port_count': {
                        'type': 'int',
                        },
                    'virtual_server': {
                        'type': 'int',
                        },
                    'disabled': {
                        'type': 'int',
                        },
                    'gslb_protocol': {
                        'type': 'int',
                        },
                    'local_protocol': {
                        'type': 'int',
                        },
                    'manually_health_check': {
                        'type': 'int',
                        },
                    'use_gslb_state': {
                        'type': 'int',
                        },
                    'dynamic': {
                        'type': 'int',
                        },
                    'ip_server_port': {
                        'type': 'list',
                        'vport': {
                            'type': 'int',
                            },
                        'vport_state': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'slb_dev_list': {
                'type': 'list',
                'device_name': {
                    'type': 'str',
                    'required': True,
                    },
                'oper': {
                    'type': 'dict',
                    'dev_name': {
                        'type': 'str',
                        },
                    'dev_ip': {
                        'type': 'str',
                        },
                    'dev_attr': {
                        'type': 'str',
                        },
                    'dev_admin_preference': {
                        'type': 'int',
                        },
                    'dev_session_num': {
                        'type': 'int',
                        },
                    'dev_session_util': {
                        'type': 'int',
                        },
                    'dev_gw_state': {
                        'type': 'str',
                        },
                    'dev_ip_cnt': {
                        'type': 'int',
                        },
                    'dev_state': {
                        'type': 'str',
                        },
                    'client_ldns_list': {
                        'type': 'list',
                        'client_ip': {
                            'type': 'str',
                            },
                        'age': {
                            'type': 'int',
                            },
                        'ntype': {
                            'type': 'str',
                            },
                        'rdt_sample1': {
                            'type': 'int',
                            },
                        'rdt_sample2': {
                            'type': 'int',
                            },
                        'rdt_sample3': {
                            'type': 'int',
                            },
                        'rdt_sample4': {
                            'type': 'int',
                            },
                        'rdt_sample5': {
                            'type': 'int',
                            },
                        'rdt_sample6': {
                            'type': 'int',
                            },
                        'rdt_sample7': {
                            'type': 'int',
                            },
                        'rdt_sample8': {
                            'type': 'int',
                            }
                        }
                    },
                'vip_server': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        },
                    'vip_server_v4_list': {
                        'type': 'list',
                        'ipv4': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            'dev_vip_addr': {
                                'type': 'str',
                                },
                            'dev_vip_state': {
                                'type': 'str',
                                },
                            'dev_vip_port_list': {
                                'type': 'list',
                                'dev_vip_port_num': {
                                    'type': 'int',
                                    },
                                'dev_vip_port_state': {
                                    'type': 'str',
                                    }
                                }
                            }
                        },
                    'vip_server_v6_list': {
                        'type': 'list',
                        'ipv6': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            'dev_vip_addr': {
                                'type': 'str',
                                },
                            'dev_vip_state': {
                                'type': 'str',
                                },
                            'dev_vip_port_list': {
                                'type': 'list',
                                'dev_vip_port_num': {
                                    'type': 'int',
                                    },
                                'dev_vip_port_state': {
                                    'type': 'str',
                                    }
                                }
                            }
                        },
                    'vip_server_name_list': {
                        'type': 'list',
                        'vip_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            'dev_vip_addr': {
                                'type': 'str',
                                },
                            'dev_vip_state': {
                                'type': 'str',
                                },
                            'dev_vip_port_list': {
                                'type': 'list',
                                'dev_vip_port_num': {
                                    'type': 'int',
                                    },
                                'dev_vip_port_state': {
                                    'type': 'str',
                                    }
                                }
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'hits': {
                'type': 'str',
                },
            'site_name': {
                'type': 'str',
                'required': True,
                },
            'ip_server_list': {
                'type': 'list',
                'ip_server_name': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                        },
                    'recent': {
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
    url_base = "/axapi/v3/gslb/site/{site_name}"

    f_dict = {}
    if '/' in str(module.params["site_name"]):
        f_dict["site_name"] = module.params["site_name"].replace("/", "%2F")
    else:
        f_dict["site_name"] = module.params["site_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/site"

    f_dict = {}
    f_dict["site_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["site"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["site"].get(k) != v:
            change_results["changed"] = True
            config_changes["site"][k] = v

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
    payload = utils.build_json("site", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["site"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["site-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["site"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["site"]["stats"] if info != "NotFound" else info
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
