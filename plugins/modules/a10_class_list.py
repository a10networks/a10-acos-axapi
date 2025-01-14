#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_class_list
description:
    - Configure classification list
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
        - "Specify name of the class list"
        type: str
        required: True
    ntype:
        description:
        - "'ac'= Make class-list type Aho-Corasick; 'dns'= Make class-list type DNS;
          'ipv4'= Make class-list type IPv4; 'ipv6'= Make class-list type IPv6; 'string'=
          Make class-list type String; 'string-case-insensitive'= Make class-list type
          String-case-insensitive. Case insensitive is applied to key string;"
        type: str
        required: False
    file:
        description:
        - "Create/Edit a class-list stored as a file"
        type: bool
        required: False
    ipv4_list:
        description:
        - "Field ipv4_list"
        type: list
        required: False
        suboptions:
            ipv4addr:
                description:
                - "Specify IP address"
                type: str
            lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
                type: int
            glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
                type: str
            shared_partition_glid:
                description:
                - "Reference a glid from shared partition"
                type: bool
            glid_shared:
                description:
                - "Use global Limit ID"
                type: str
            lsn_lid:
                description:
                - "LSN Limit ID (LID index)"
                type: int
            lsn_radius_profile:
                description:
                - "LSN RADIUS Profile Index"
                type: int
            gtp_rate_limit_policy_v4:
                description:
                - "GTP Rate Limit Template Name"
                type: str
            age:
                description:
                - "Specify age in minutes"
                type: int
    ipv6_list:
        description:
        - "Field ipv6_list"
        type: list
        required: False
        suboptions:
            ipv6_addr:
                description:
                - "Specify IPv6 host or subnet"
                type: str
            v6_lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
                type: int
            v6_glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
                type: str
            shared_partition_v6_glid:
                description:
                - "Reference a glid from shared partition"
                type: bool
            v6_glid_shared:
                description:
                - "Use global Limit ID"
                type: str
            v6_lsn_lid:
                description:
                - "LSN Limit ID (LID index)"
                type: int
            v6_lsn_radius_profile:
                description:
                - "LSN RADIUS Profile Index"
                type: int
            gtp_rate_limit_policy_v6:
                description:
                - "GTP Rate Limit Template Name"
                type: str
            v6_age:
                description:
                - "Specify age in minutes"
                type: int
    dns:
        description:
        - "Field dns"
        type: list
        required: False
        suboptions:
            dns_match_type:
                description:
                - "'contains'= Domain contains another string; 'ends-with'= Domain ends with
          another string; 'starts-with'= Domain starts-with another string;"
                type: str
            dns_match_string:
                description:
                - "Domain name"
                type: str
            dns_lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
                type: int
            dns_glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
                type: str
            shared_partition_dns_glid:
                description:
                - "Reference a glid from shared partition"
                type: bool
            dns_glid_shared:
                description:
                - "Use global Limit ID"
                type: str
    str_list:
        description:
        - "Field str_list"
        type: list
        required: False
        suboptions:
            str:
                description:
                - "Specify key string"
                type: str
            str_lid_dummy:
                description:
                - "Use Limit ID defined in template"
                type: bool
            str_lid:
                description:
                - "LID index"
                type: int
            str_glid_dummy:
                description:
                - "Use global Limit ID"
                type: bool
            str_glid:
                description:
                - "Global LID index"
                type: str
            shared_partition_str_glid:
                description:
                - "Reference a glid from shared partition"
                type: bool
            str_glid_shared:
                description:
                - "Use global Limit ID"
                type: str
            value_str:
                description:
                - "Specify value string"
                type: str
    ac_list:
        description:
        - "Field ac_list"
        type: list
        required: False
        suboptions:
            ac_match_type:
                description:
                - "'contains'= String contains another string; 'ends-with'= String ends with
          another string; 'equals'= String equals another string; 'starts-with'= String
          starts with another string;"
                type: str
            ac_key_string:
                description:
                - "Specify key string"
                type: str
            ac_value:
                description:
                - "Specify value string"
                type: str
            gtp_rate_limit_policy_str:
                description:
                - "GTP Rate Limit Template Name"
                type: str
    geo_list:
        description:
        - "Field geo_list"
        type: list
        required: False
        suboptions:
            geo_location:
                description:
                - "Specify geo-location"
                type: str
            geo_location_ipv6:
                description:
                - "Specify IPv6 geo-location"
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
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ntype:
                description:
                - "Field type"
                type: str
            file_or_string:
                description:
                - "Field file_or_string"
                type: str
            user_tag:
                description:
                - "Field user_tag"
                type: str
            ipv4_total_single_ip:
                description:
                - "Field ipv4_total_single_ip"
                type: int
            ipv4_total_subnet:
                description:
                - "Field ipv4_total_subnet"
                type: int
            ipv6_total_single_ip:
                description:
                - "Field ipv6_total_single_ip"
                type: int
            ipv6_total_subnet:
                description:
                - "Field ipv6_total_subnet"
                type: int
            dns_total_entries:
                description:
                - "Field dns_total_entries"
                type: int
            string_total_entries:
                description:
                - "Field string_total_entries"
                type: int
            ac_total_entries:
                description:
                - "Field ac_total_entries"
                type: int
            geo_location_total_entries:
                description:
                - "Field geo_location_total_entries"
                type: int
            ipv4_entries:
                description:
                - "Field ipv4_entries"
                type: list
            ipv6_entries:
                description:
                - "Field ipv6_entries"
                type: list
            dns_entries:
                description:
                - "Field dns_entries"
                type: list
            string_entries:
                description:
                - "Field string_entries"
                type: list
            ac_entries:
                description:
                - "Field ac_entries"
                type: list
            geo_location_entries:
                description:
                - "Field geo_location_entries"
                type: list
            name:
                description:
                - "Specify name of the class list"
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
AVAILABLE_PROPERTIES = ["ac_list", "dns", "file", "geo_list", "ipv4_list", "ipv6_list", "name", "oper", "str_list", "ntype", "user_tag", "uuid", ]


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
        'ntype': {
            'type': 'str',
            'choices': ['ac', 'dns', 'ipv4', 'ipv6', 'string', 'string-case-insensitive']
            },
        'file': {
            'type': 'bool',
            },
        'ipv4_list': {
            'type': 'list',
            'ipv4addr': {
                'type': 'str',
                },
            'lid': {
                'type': 'int',
                },
            'glid': {
                'type': 'str',
                },
            'shared_partition_glid': {
                'type': 'bool',
                },
            'glid_shared': {
                'type': 'str',
                },
            'lsn_lid': {
                'type': 'int',
                },
            'lsn_radius_profile': {
                'type': 'int',
                },
            'gtp_rate_limit_policy_v4': {
                'type': 'str',
                },
            'age': {
                'type': 'int',
                }
            },
        'ipv6_list': {
            'type': 'list',
            'ipv6_addr': {
                'type': 'str',
                },
            'v6_lid': {
                'type': 'int',
                },
            'v6_glid': {
                'type': 'str',
                },
            'shared_partition_v6_glid': {
                'type': 'bool',
                },
            'v6_glid_shared': {
                'type': 'str',
                },
            'v6_lsn_lid': {
                'type': 'int',
                },
            'v6_lsn_radius_profile': {
                'type': 'int',
                },
            'gtp_rate_limit_policy_v6': {
                'type': 'str',
                },
            'v6_age': {
                'type': 'int',
                }
            },
        'dns': {
            'type': 'list',
            'dns_match_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'starts-with']
                },
            'dns_match_string': {
                'type': 'str',
                },
            'dns_lid': {
                'type': 'int',
                },
            'dns_glid': {
                'type': 'str',
                },
            'shared_partition_dns_glid': {
                'type': 'bool',
                },
            'dns_glid_shared': {
                'type': 'str',
                }
            },
        'str_list': {
            'type': 'list',
            'str': {
                'type': 'str',
                },
            'str_lid_dummy': {
                'type': 'bool',
                },
            'str_lid': {
                'type': 'int',
                },
            'str_glid_dummy': {
                'type': 'bool',
                },
            'str_glid': {
                'type': 'str',
                },
            'shared_partition_str_glid': {
                'type': 'bool',
                },
            'str_glid_shared': {
                'type': 'str',
                },
            'value_str': {
                'type': 'str',
                }
            },
        'ac_list': {
            'type': 'list',
            'ac_match_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with']
                },
            'ac_key_string': {
                'type': 'str',
                },
            'ac_value': {
                'type': 'str',
                },
            'gtp_rate_limit_policy_str': {
                'type': 'str',
                }
            },
        'geo_list': {
            'type': 'list',
            'geo_location': {
                'type': 'str',
                },
            'geo_location_ipv6': {
                'type': 'str',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'oper': {
            'type': 'dict',
            'ntype': {
                'type': 'str',
                'choices': ['ac', 'dns', 'ipv4', 'ipv6', 'string', 'string-case-insensitive', '[ipv4]', '[ipv6]', '[dns]', '[dns, ipv4]', '[dns, ipv6]']
                },
            'file_or_string': {
                'type': 'str',
                'choices': ['file', 'config']
                },
            'user_tag': {
                'type': 'str',
                },
            'ipv4_total_single_ip': {
                'type': 'int',
                },
            'ipv4_total_subnet': {
                'type': 'int',
                },
            'ipv6_total_single_ip': {
                'type': 'int',
                },
            'ipv6_total_subnet': {
                'type': 'int',
                },
            'dns_total_entries': {
                'type': 'int',
                },
            'string_total_entries': {
                'type': 'int',
                },
            'ac_total_entries': {
                'type': 'int',
                },
            'geo_location_total_entries': {
                'type': 'int',
                },
            'ipv4_entries': {
                'type': 'list',
                'ipv4_addr': {
                    'type': 'str',
                    },
                'ipv4_lid': {
                    'type': 'int',
                    },
                'ipv4_glid': {
                    'type': 'int',
                    },
                'ipv4_lsn_lid': {
                    'type': 'int',
                    },
                'ipv4_lsn_radius_profile': {
                    'type': 'int',
                    },
                'ipv4_gtp_policy': {
                    'type': 'str',
                    },
                'ipv4_category': {
                    'type': 'int',
                    },
                'ipv4_hit_count': {
                    'type': 'int',
                    },
                'ipv4_age': {
                    'type': 'int',
                    },
                'ipv4_rpz_type': {
                    'type': 'int',
                    }
                },
            'ipv6_entries': {
                'type': 'list',
                'ipv6addr': {
                    'type': 'str',
                    },
                'ipv6_lid': {
                    'type': 'int',
                    },
                'ipv6_glid': {
                    'type': 'int',
                    },
                'ipv6_lsn_lid': {
                    'type': 'int',
                    },
                'ipv6_lsn_radius_profile': {
                    'type': 'int',
                    },
                'ipv6_gtp_policy': {
                    'type': 'str',
                    },
                'ipv6_category': {
                    'type': 'int',
                    },
                'ipv6_hit_count': {
                    'type': 'int',
                    },
                'ipv6_age': {
                    'type': 'int',
                    },
                'ipv6_rpz_type': {
                    'type': 'int',
                    }
                },
            'dns_entries': {
                'type': 'list',
                'dns_match_type': {
                    'type': 'str',
                    'choices': ['contains', 'ends-with', 'starts-with']
                    },
                'dns_match_string': {
                    'type': 'str',
                    },
                'dns_lid': {
                    'type': 'int',
                    },
                'dns_glid': {
                    'type': 'int',
                    },
                'dns_hit_count': {
                    'type': 'int',
                    },
                'dns_rpz_type': {
                    'type': 'int',
                    }
                },
            'string_entries': {
                'type': 'list',
                'string_key': {
                    'type': 'str',
                    },
                'string_value': {
                    'type': 'str',
                    },
                'string_lid': {
                    'type': 'int',
                    },
                'string_glid': {
                    'type': 'int',
                    },
                'string_hit_count': {
                    'type': 'int',
                    }
                },
            'ac_entries': {
                'type': 'list',
                'ac_match_type': {
                    'type': 'str',
                    'choices': ['contains', 'ends-with', 'starts-with', 'equals']
                    },
                'ac_match_string': {
                    'type': 'str',
                    },
                'ac_match_value': {
                    'type': 'str',
                    },
                'ac_hit_count': {
                    'type': 'int',
                    },
                'ac_gtp_policy': {
                    'type': 'str',
                    }
                },
            'geo_location_entries': {
                'type': 'list',
                'geo_location': {
                    'type': 'str',
                    },
                'geo_location_status': {
                    'type': 'str',
                    }
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
    url_base = "/axapi/v3/class-list/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/class-list"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["class-list"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["class-list"].get(k) != v:
            change_results["changed"] = True
            config_changes["class-list"][k] = v

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
    payload = utils.build_json("class-list", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["class-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["class-list-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["class-list"]["oper"] if info != "NotFound" else info
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
