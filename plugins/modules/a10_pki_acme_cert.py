#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_pki_acme_cert
description:
    - ACME Certificate enrollment object
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
        - "Specify Certificate name to be enrolled"
        type: str
        required: True
    url:
        description:
        - "ACME directory URL. By default, use Let's encrypt as CA server"
        type: str
        required: False
    staging_url:
        description:
        - "ACME staging directory URL. By default, use Let's encrypt as CA server"
        type: str
        required: False
    domain:
        description:
        - "Main domain you want to issue the cert for. CA will verify whether you control
          this domain"
        type: str
        required: False
    san_domain:
        description:
        - "Subject-alternate-name dns(s) for your cert, sperated by /"
        type: str
        required: False
    enroll:
        description:
        - "Initiates enrollment with CA. Due to CA rate limit, A10 strongly recommend you
          set 'run-with-staging-server' during test"
        type: bool
        required: False
    force:
        description:
        - "Ignore the next renewal time and force to renew cert"
        type: bool
        required: False
    staging:
        description:
        - "Run ACME operation with staging server. Due to CA rate limit, A10 strongly
          recommends you set this during test"
        type: bool
        required: False
    log_level:
        description:
        - "Level for logging output of ACME commands(default 1 and detailed 2, including
          debug messages)"
        type: int
        required: False
    renew_before:
        description:
        - "Specify interval before certificate expiry to renew the certificate"
        type: bool
        required: False
    renew_before_type:
        description:
        - "'hour'= Number of hours before cert expiry; 'day'= Number of days before cert
          expiry; 'week'= Number of weeks before cert expiry; 'month'= Number of months
          before cert expiry(1 month=30 days);"
        type: str
        required: False
    renew_before_value:
        description:
        - "Value of renewal period"
        type: int
        required: False
    renew_every:
        description:
        - "Specify periodic interval in which to renew the certificate"
        type: bool
        required: False
    minute:
        description:
        - "Periodic interval in minutes"
        type: int
        required: False
    renew_every_type:
        description:
        - "'hour'= Periodic interval in hours; 'day'= Periodic interval in days; 'week'=
          Periodic interval in weeks; 'month'= Periodic interval in months(1 month=30
          days);"
        type: str
        required: False
    renew_every_value:
        description:
        - "Value of renewal period"
        type: int
        required: False
    cert_type:
        description:
        - "Specify the type of certificate"
        type: bool
        required: False
    rsa_type:
        description:
        - "RSA certificate (default)"
        type: bool
        required: False
    ecdsa_type:
        description:
        - "ECDSA certificate"
        type: bool
        required: False
    rsa_key_length:
        description:
        - "'2048'= Key size 2048 bits(default); '3072'= Key size 3072 bits; '4096'= Key
          size 4096 bits; '8192'= Key size 8192 bits;"
        type: str
        required: False
    ec_key_length:
        description:
        - "'256'= Key size 256 bits; '384'= Key size 384 bits(default);"
        type: str
        required: False
    email:
        description:
        - "A valid email address for your ACME account. CA uses this email to send you
          expiration or other notices"
        type: str
        required: False
    vrid:
        description:
        - "Specify ha VRRP-A vrid. It is used to sync http-01 challenge token"
        type: int
        required: False
    eab_key_id:
        description:
        - "The key identifier for ACME External Account Binding"
        type: str
        required: False
    eab_hmac_key:
        description:
        - "The HMAC key for ACME External Account Binding"
        type: bool
        required: False
    secret_string:
        description:
        - "The HMAC key for ACME External Account Binding"
        type: str
        required: False
    encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
        type: str
        required: False
    acme_client:
        description:
        - "'agent-v1'= Set agent-v1 as the ACME client (default); 'agent-v2'= Set agent-v2
          as the ACME client;"
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
    "acme_client", "cert_type", "domain", "eab_hmac_key", "eab_key_id", "ec_key_length", "ecdsa_type", "email", "encrypted", "enroll", "force", "log_level", "minute", "name", "renew_before", "renew_before_type", "renew_before_value", "renew_every", "renew_every_type", "renew_every_value", "rsa_key_length", "rsa_type", "san_domain", "secret_string",
    "staging", "staging_url", "url", "user_tag", "uuid", "vrid",
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
        'url': {
            'type': 'str',
            },
        'staging_url': {
            'type': 'str',
            },
        'domain': {
            'type': 'str',
            },
        'san_domain': {
            'type': 'str',
            },
        'enroll': {
            'type': 'bool',
            },
        'force': {
            'type': 'bool',
            },
        'staging': {
            'type': 'bool',
            },
        'log_level': {
            'type': 'int',
            },
        'renew_before': {
            'type': 'bool',
            },
        'renew_before_type': {
            'type': 'str',
            'choices': ['hour', 'day', 'week', 'month']
            },
        'renew_before_value': {
            'type': 'int',
            },
        'renew_every': {
            'type': 'bool',
            },
        'minute': {
            'type': 'int',
            },
        'renew_every_type': {
            'type': 'str',
            'choices': ['hour', 'day', 'week', 'month']
            },
        'renew_every_value': {
            'type': 'int',
            },
        'cert_type': {
            'type': 'bool',
            },
        'rsa_type': {
            'type': 'bool',
            },
        'ecdsa_type': {
            'type': 'bool',
            },
        'rsa_key_length': {
            'type': 'str',
            'choices': ['2048', '3072', '4096', '8192']
            },
        'ec_key_length': {
            'type': 'str',
            'choices': ['256', '384']
            },
        'email': {
            'type': 'str',
            },
        'vrid': {
            'type': 'int',
            },
        'eab_key_id': {
            'type': 'str',
            },
        'eab_hmac_key': {
            'type': 'bool',
            },
        'secret_string': {
            'type': 'str',
            },
        'encrypted': {
            'type': 'str',
            },
        'acme_client': {
            'type': 'str',
            'choices': ['agent-v1', 'agent-v2']
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/pki/acme-cert/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/pki/acme-cert"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["acme-cert"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["acme-cert"].get(k) != v:
            change_results["changed"] = True
            config_changes["acme-cert"][k] = v

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
    payload = utils.build_json("acme-cert", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["acme-cert"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["acme-cert-list"] if info != "NotFound" else info
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
