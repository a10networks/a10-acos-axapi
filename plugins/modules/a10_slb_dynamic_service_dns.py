#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_dynamic_service_dns
description:
    - Dynamic-service DNS Statistics
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
                - "'all'= all; 'n_query'= Number of queries; 'n_query_err'= Number of query
          errors; 'n_query_drop'= Number of queries dropped due to full queue; 'n_resp'=
          Number of responses; 'n_resp_err'= Number of response errors;
          'n_resp_f_formerr'= Number of response failure with rcode FormErr;
          'n_resp_f_servfail'= Number of response failure with rcode ServFail;
          'n_resp_f_nxdomain'= Number of response failure with rcode NXDomain;
          'n_resp_f_notimp'= Number of response failure with rcode NotImp;
          'n_resp_f_refused'= Number of response failure with rcode Refused;
          'n_resp_f_yxdomain'= Number of response failure with rcode YXDomain;
          'n_resp_f_yxrrset'= Number of response failure with rcode YXRRSet;
          'n_resp_f_nxrrset'= Number of response failure with rcode NXRRSet;
          'n_resp_f_notauth'= Number of response failure with rcode NotAuth;
          'n_resp_f_notzone'= Number of response failure with rcode NotZone;
          'n_resp_f_dsotypeni'= Number of response failure with rcode DSOTYPENI;
          'n_resp_f_badvers'= Number of response failure with rcode BADVERS;
          'n_resp_f_badkey'= Number of response failure with rcode BADKEY;
          'n_resp_f_badtime'= Number of response failure with rcode BADTIME;
          'n_resp_f_badmode'= Number of response failure with rcode BADMODE;
          'n_resp_f_badname'= Number of response failure with rcode BADNAME;
          'n_resp_f_badalg'= Number of response failure with rcode BADALG;
          'n_resp_f_badtrunc'= Number of response failure with rcode BADTRUNC;
          'n_resp_f_badcookie'= Number of response failure with rcode BADCOOKIE;
          'n_resp_f_invalid'= Number of response failure with invalid rcode;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            n_query:
                description:
                - "Number of queries"
                type: str
            n_query_err:
                description:
                - "Number of query errors"
                type: str
            n_query_drop:
                description:
                - "Number of queries dropped due to full queue"
                type: str
            n_resp:
                description:
                - "Number of responses"
                type: str
            n_resp_err:
                description:
                - "Number of response errors"
                type: str
            n_resp_f_formerr:
                description:
                - "Number of response failure with rcode FormErr"
                type: str
            n_resp_f_servfail:
                description:
                - "Number of response failure with rcode ServFail"
                type: str
            n_resp_f_nxdomain:
                description:
                - "Number of response failure with rcode NXDomain"
                type: str
            n_resp_f_notimp:
                description:
                - "Number of response failure with rcode NotImp"
                type: str
            n_resp_f_refused:
                description:
                - "Number of response failure with rcode Refused"
                type: str
            n_resp_f_yxdomain:
                description:
                - "Number of response failure with rcode YXDomain"
                type: str
            n_resp_f_yxrrset:
                description:
                - "Number of response failure with rcode YXRRSet"
                type: str
            n_resp_f_nxrrset:
                description:
                - "Number of response failure with rcode NXRRSet"
                type: str
            n_resp_f_notauth:
                description:
                - "Number of response failure with rcode NotAuth"
                type: str
            n_resp_f_notzone:
                description:
                - "Number of response failure with rcode NotZone"
                type: str
            n_resp_f_dsotypeni:
                description:
                - "Number of response failure with rcode DSOTYPENI"
                type: str
            n_resp_f_badvers:
                description:
                - "Number of response failure with rcode BADVERS"
                type: str
            n_resp_f_badkey:
                description:
                - "Number of response failure with rcode BADKEY"
                type: str
            n_resp_f_badtime:
                description:
                - "Number of response failure with rcode BADTIME"
                type: str
            n_resp_f_badmode:
                description:
                - "Number of response failure with rcode BADMODE"
                type: str
            n_resp_f_badname:
                description:
                - "Number of response failure with rcode BADNAME"
                type: str
            n_resp_f_badalg:
                description:
                - "Number of response failure with rcode BADALG"
                type: str
            n_resp_f_badtrunc:
                description:
                - "Number of response failure with rcode BADTRUNC"
                type: str
            n_resp_f_badcookie:
                description:
                - "Number of response failure with rcode BADCOOKIE"
                type: str
            n_resp_f_invalid:
                description:
                - "Number of response failure with invalid rcode"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'n_query', 'n_query_err', 'n_query_drop', 'n_resp', 'n_resp_err', 'n_resp_f_formerr', 'n_resp_f_servfail', 'n_resp_f_nxdomain', 'n_resp_f_notimp', 'n_resp_f_refused', 'n_resp_f_yxdomain', 'n_resp_f_yxrrset', 'n_resp_f_nxrrset', 'n_resp_f_notauth', 'n_resp_f_notzone', 'n_resp_f_dsotypeni', 'n_resp_f_badvers',
                    'n_resp_f_badkey', 'n_resp_f_badtime', 'n_resp_f_badmode', 'n_resp_f_badname', 'n_resp_f_badalg', 'n_resp_f_badtrunc', 'n_resp_f_badcookie', 'n_resp_f_invalid'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'n_query': {
                'type': 'str',
                },
            'n_query_err': {
                'type': 'str',
                },
            'n_query_drop': {
                'type': 'str',
                },
            'n_resp': {
                'type': 'str',
                },
            'n_resp_err': {
                'type': 'str',
                },
            'n_resp_f_formerr': {
                'type': 'str',
                },
            'n_resp_f_servfail': {
                'type': 'str',
                },
            'n_resp_f_nxdomain': {
                'type': 'str',
                },
            'n_resp_f_notimp': {
                'type': 'str',
                },
            'n_resp_f_refused': {
                'type': 'str',
                },
            'n_resp_f_yxdomain': {
                'type': 'str',
                },
            'n_resp_f_yxrrset': {
                'type': 'str',
                },
            'n_resp_f_nxrrset': {
                'type': 'str',
                },
            'n_resp_f_notauth': {
                'type': 'str',
                },
            'n_resp_f_notzone': {
                'type': 'str',
                },
            'n_resp_f_dsotypeni': {
                'type': 'str',
                },
            'n_resp_f_badvers': {
                'type': 'str',
                },
            'n_resp_f_badkey': {
                'type': 'str',
                },
            'n_resp_f_badtime': {
                'type': 'str',
                },
            'n_resp_f_badmode': {
                'type': 'str',
                },
            'n_resp_f_badname': {
                'type': 'str',
                },
            'n_resp_f_badalg': {
                'type': 'str',
                },
            'n_resp_f_badtrunc': {
                'type': 'str',
                },
            'n_resp_f_badcookie': {
                'type': 'str',
                },
            'n_resp_f_invalid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/dynamic-service-dns"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/dynamic-service-dns"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dynamic-service-dns"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dynamic-service-dns"].get(k) != v:
            change_results["changed"] = True
            config_changes["dynamic-service-dns"][k] = v

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
    payload = utils.build_json("dynamic-service-dns", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dynamic-service-dns"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dynamic-service-dns-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["dynamic-service-dns"]["stats"] if info != "NotFound" else info
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
