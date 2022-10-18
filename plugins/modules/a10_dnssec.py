#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_dnssec
description:
    - Domain Name System Security Extensions commands
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
    standalone:
        description:
        - "Run DNSSEC in standalone mode, in GSLB group mode by default"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    dnskey:
        description:
        - "Field dnskey"
        type: dict
        required: False
        suboptions:
            key_delete:
                description:
                - "Delete the DNSKEY file"
                type: bool
            zone_name:
                description:
                - "DNS zone name of the child zone"
                type: str
    ds:
        description:
        - "Field ds"
        type: dict
        required: False
        suboptions:
            ds_delete:
                description:
                - "Delete the DS file"
                type: bool
            zone_name:
                description:
                - "DNS zone name of the child zone"
                type: str
    sign_zone_now:
        description:
        - "Field sign_zone_now"
        type: dict
        required: False
        suboptions:
            zone_name:
                description:
                - "Specify the name for the DNS zone, empty means sign all zones"
                type: str
    key_rollover:
        description:
        - "Field key_rollover"
        type: dict
        required: False
        suboptions:
            zone_name:
                description:
                - "Specify the name for the DNS zone"
                type: str
            dnssec_key_type:
                description:
                - "'ZSK'= Zone Signing Key; 'KSK'= Key Signing Key;"
                type: str
            zsk_start:
                description:
                - "start ZSK rollover in emergency mode"
                type: bool
            ksk_start:
                description:
                - "start KSK rollover in emergency mode"
                type: bool
            ds_ready_in_parent_zone:
                description:
                - "DS RR is already ready in the parent zone"
                type: bool
    template_list:
        description:
        - "Field template_list"
        type: list
        required: False
        suboptions:
            dnssec_temp_name:
                description:
                - "DNSSEC Template Name"
                type: str
            algorithm:
                description:
                - "'RSASHA1'= RSASHA1 algorithm; 'RSASHA256'= RSASHA256 algorithm; 'RSASHA512'=
          RSASHA512 algorithm;"
                type: str
            combinations_limit:
                description:
                - "the max number of combinations per RRset (Default value is 31)"
                type: int
            dnskey_ttl_k:
                description:
                - "The TTL value of DNSKEY RR"
                type: bool
            dnskey_ttl_v:
                description:
                - "in seconds, 14400 seconds by default"
                type: int
            enable_nsec3:
                description:
                - "enable NSEC3 support. disabled by default"
                type: bool
            return_nsec_on_failure:
                description:
                - "return NSEC/NSEC3 or not on failure case. return by default"
                type: bool
            signature_validity_period_k:
                description:
                - "The period that a signature is valid"
                type: bool
            signature_validity_period_v:
                description:
                - "in days, 10 days by default"
                type: int
            hsm:
                description:
                - "specify the HSM template"
                type: str
            dnssec_template_zsk:
                description:
                - "Field dnssec_template_zsk"
                type: dict
            dnssec_template_ksk:
                description:
                - "Field dnssec_template_ksk"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            soa_memory:
                description:
                - "Field soa_memory"
                type: int
            soa_objects:
                description:
                - "Field soa_objects"
                type: int
            dnskey_memory:
                description:
                - "Field dnskey_memory"
                type: int
            dnskey_objects:
                description:
                - "Field dnskey_objects"
                type: int
            ds_memory:
                description:
                - "Field ds_memory"
                type: int
            ds_objects:
                description:
                - "Field ds_objects"
                type: int
            nsec3param_memory:
                description:
                - "Field nsec3param_memory"
                type: int
            nsec3param_objects:
                description:
                - "Field nsec3param_objects"
                type: int
            nsec_memory:
                description:
                - "Field nsec_memory"
                type: int
            nsec_objects:
                description:
                - "Field nsec_objects"
                type: int
            nsec3_memory:
                description:
                - "Field nsec3_memory"
                type: int
            nsec3_objects:
                description:
                - "Field nsec3_objects"
                type: int
            rrsig_memory:
                description:
                - "Field rrsig_memory"
                type: int
            rrsig_objects:
                description:
                - "Field rrsig_objects"
                type: int
            a_memory:
                description:
                - "Field a_memory"
                type: int
            a_objects:
                description:
                - "Field a_objects"
                type: int
            aaaa_memory:
                description:
                - "Field aaaa_memory"
                type: int
            aaaa_objects:
                description:
                - "Field aaaa_objects"
                type: int
            ptr_memory:
                description:
                - "Field ptr_memory"
                type: int
            ptr_objects:
                description:
                - "Field ptr_objects"
                type: int
            cname_memory:
                description:
                - "Field cname_memory"
                type: int
            cname_objects:
                description:
                - "Field cname_objects"
                type: int
            ns_memory:
                description:
                - "Field ns_memory"
                type: int
            ns_objects:
                description:
                - "Field ns_objects"
                type: int
            mx_memory:
                description:
                - "Field mx_memory"
                type: int
            mx_objects:
                description:
                - "Field mx_objects"
                type: int
            srv_memory:
                description:
                - "Field srv_memory"
                type: int
            srv_objects:
                description:
                - "Field srv_objects"
                type: int
            txt_memory:
                description:
                - "Field txt_memory"
                type: int
            txt_objects:
                description:
                - "Field txt_objects"
                type: int
            zone_memory:
                description:
                - "Field zone_memory"
                type: int
            zone_objects:
                description:
                - "Field zone_objects"
                type: int
            domain_memory:
                description:
                - "Field domain_memory"
                type: int
            domain_objects:
                description:
                - "Field domain_objects"
                type: int
            table_memory:
                description:
                - "Field table_memory"
                type: int
            table_objects:
                description:
                - "Field table_objects"
                type: int
            reference_memory:
                description:
                - "Field reference_memory"
                type: int
            reference_objects:
                description:
                - "Field reference_objects"
                type: int
            array_memory:
                description:
                - "Field array_memory"
                type: int
            array_objects:
                description:
                - "Field array_objects"
                type: int
            rrsig2_memory:
                description:
                - "Field rrsig2_memory"
                type: int
            rrsig2_objects:
                description:
                - "Field rrsig2_objects"
                type: int
            total_memory:
                description:
                - "Field total_memory"
                type: int
            total_objects:
                description:
                - "Field total_objects"
                type: int

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
AVAILABLE_PROPERTIES = ["dnskey", "ds", "key_rollover", "oper", "sign_zone_now", "standalone", "template_list", "uuid", ]


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
        'standalone': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'dnskey': {
            'type': 'dict',
            'key_delete': {
                'type': 'bool',
                },
            'zone_name': {
                'type': 'str',
                }
            },
        'ds': {
            'type': 'dict',
            'ds_delete': {
                'type': 'bool',
                },
            'zone_name': {
                'type': 'str',
                }
            },
        'sign_zone_now': {
            'type': 'dict',
            'zone_name': {
                'type': 'str',
                }
            },
        'key_rollover': {
            'type': 'dict',
            'zone_name': {
                'type': 'str',
                },
            'dnssec_key_type': {
                'type': 'str',
                'choices': ['ZSK', 'KSK']
                },
            'zsk_start': {
                'type': 'bool',
                },
            'ksk_start': {
                'type': 'bool',
                },
            'ds_ready_in_parent_zone': {
                'type': 'bool',
                }
            },
        'template_list': {
            'type': 'list',
            'dnssec_temp_name': {
                'type': 'str',
                'required': True,
                },
            'algorithm': {
                'type': 'str',
                'choices': ['RSASHA1', 'RSASHA256', 'RSASHA512']
                },
            'combinations_limit': {
                'type': 'int',
                },
            'dnskey_ttl_k': {
                'type': 'bool',
                },
            'dnskey_ttl_v': {
                'type': 'int',
                },
            'enable_nsec3': {
                'type': 'bool',
                },
            'return_nsec_on_failure': {
                'type': 'bool',
                },
            'signature_validity_period_k': {
                'type': 'bool',
                },
            'signature_validity_period_v': {
                'type': 'int',
                },
            'hsm': {
                'type': 'str',
                },
            'dnssec_template_zsk': {
                'type': 'dict',
                'zsk_keysize_k': {
                    'type': 'bool',
                    },
                'zsk_keysize_v': {
                    'type': 'int',
                    },
                'zsk_lifetime_k': {
                    'type': 'bool',
                    },
                'zsk_lifetime_v': {
                    'type': 'int',
                    },
                'zsk_rollover_time_k': {
                    'type': 'bool',
                    },
                'zsk_rollover_time_v': {
                    'type': 'int',
                    }
                },
            'dnssec_template_ksk': {
                'type': 'dict',
                'ksk_keysize_k': {
                    'type': 'bool',
                    },
                'ksk_keysize_v': {
                    'type': 'int',
                    },
                'ksk_lifetime_k': {
                    'type': 'bool',
                    },
                'ksk_lifetime_v': {
                    'type': 'int',
                    },
                'ksk_rollover_time_k': {
                    'type': 'bool',
                    },
                'zsk_rollover_time_v': {
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
        'oper': {
            'type': 'dict',
            'soa_memory': {
                'type': 'int',
                },
            'soa_objects': {
                'type': 'int',
                },
            'dnskey_memory': {
                'type': 'int',
                },
            'dnskey_objects': {
                'type': 'int',
                },
            'ds_memory': {
                'type': 'int',
                },
            'ds_objects': {
                'type': 'int',
                },
            'nsec3param_memory': {
                'type': 'int',
                },
            'nsec3param_objects': {
                'type': 'int',
                },
            'nsec_memory': {
                'type': 'int',
                },
            'nsec_objects': {
                'type': 'int',
                },
            'nsec3_memory': {
                'type': 'int',
                },
            'nsec3_objects': {
                'type': 'int',
                },
            'rrsig_memory': {
                'type': 'int',
                },
            'rrsig_objects': {
                'type': 'int',
                },
            'a_memory': {
                'type': 'int',
                },
            'a_objects': {
                'type': 'int',
                },
            'aaaa_memory': {
                'type': 'int',
                },
            'aaaa_objects': {
                'type': 'int',
                },
            'ptr_memory': {
                'type': 'int',
                },
            'ptr_objects': {
                'type': 'int',
                },
            'cname_memory': {
                'type': 'int',
                },
            'cname_objects': {
                'type': 'int',
                },
            'ns_memory': {
                'type': 'int',
                },
            'ns_objects': {
                'type': 'int',
                },
            'mx_memory': {
                'type': 'int',
                },
            'mx_objects': {
                'type': 'int',
                },
            'srv_memory': {
                'type': 'int',
                },
            'srv_objects': {
                'type': 'int',
                },
            'txt_memory': {
                'type': 'int',
                },
            'txt_objects': {
                'type': 'int',
                },
            'zone_memory': {
                'type': 'int',
                },
            'zone_objects': {
                'type': 'int',
                },
            'domain_memory': {
                'type': 'int',
                },
            'domain_objects': {
                'type': 'int',
                },
            'table_memory': {
                'type': 'int',
                },
            'table_objects': {
                'type': 'int',
                },
            'reference_memory': {
                'type': 'int',
                },
            'reference_objects': {
                'type': 'int',
                },
            'array_memory': {
                'type': 'int',
                },
            'array_objects': {
                'type': 'int',
                },
            'rrsig2_memory': {
                'type': 'int',
                },
            'rrsig2_objects': {
                'type': 'int',
                },
            'total_memory': {
                'type': 'int',
                },
            'total_objects': {
                'type': 'int',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/dnssec"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/dnssec"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dnssec"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dnssec"].get(k) != v:
            change_results["changed"] = True
            config_changes["dnssec"][k] = v

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
    payload = utils.build_json("dnssec", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dnssec"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dnssec-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["dnssec"]["oper"] if info != "NotFound" else info
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
