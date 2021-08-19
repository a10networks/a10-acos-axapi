#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_icap_http
description:
    - Configure ICAP
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
                - "'all'= all; 'status_200'= Status code 200; 'status_201'= Status code 201;
          'status_202'= Status code 202; 'status_203'= Status code 203; 'status_204'=
          Status code 204; 'status_205'= Status code 205; 'status_206'= Status code 206;
          'status_207'= Status code 207; 'status_100'= Status code 100; 'status_101'=
          Status code 101; 'status_102'= Status code 102; 'status_300'= Status code 300;
          'status_301'= Status code 301; 'status_302'= Status code 302; 'status_303'=
          Status code 303; 'status_304'= Status code 304; 'status_305'= Status code 305;
          'status_306'= Status code 306; 'status_307'= Status code 307; 'status_400'=
          Status code 400; 'status_401'= Status code 401; 'status_402'= Status code 402;
          'status_403'= Status code 403; 'status_404'= Status code 404; 'status_405'=
          Status code 405; 'status_406'= Status code 406; 'status_407'= Status code 407;
          'status_408'= Status code 408; 'status_409'= Status code 409; 'status_410'=
          Status code 410; 'status_411'= Status code 411; 'status_412'= Status code 412;
          'status_413'= Status code 413; 'status_414'= Status code 414; 'status_415'=
          Status code 415; 'status_416'= Status code 416; 'status_417'= Status code 417;
          'status_418'= Status code 418; 'status_422'= Status code 422; 'status_423'=
          Status code 423; 'status_424'= Status code 424; 'status_425'= Status code 425;
          'status_426'= Status code 426; 'status_449'= Status code 449; 'status_450'=
          Status code 450; 'status_500'= Status code 500; 'status_501'= Status code 501;
          'status_502'= Status code 502; 'status_503'= Status code 503; 'status_504'=
          Status code 504; 'status_505'= Status code 505; 'status_506'= Status code 506;
          'status_507'= Status code 507; 'status_508'= Status code 508; 'status_509'=
          Status code 509; 'status_510'= Status code 510; 'status_1xx'= status code 1XX;
          'status_2xx'= status code 2XX; 'status_3xx'= status code 3XX; 'status_4xx'=
          status code 4XX; 'status_5xx'= status code 5XX; 'status_6xx'= status code 6XX;
          'status_unknown'= Status code unknown;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            status_200:
                description:
                - "Status code 200"
                type: str
            status_201:
                description:
                - "Status code 201"
                type: str
            status_202:
                description:
                - "Status code 202"
                type: str
            status_203:
                description:
                - "Status code 203"
                type: str
            status_204:
                description:
                - "Status code 204"
                type: str
            status_205:
                description:
                - "Status code 205"
                type: str
            status_206:
                description:
                - "Status code 206"
                type: str
            status_207:
                description:
                - "Status code 207"
                type: str
            status_100:
                description:
                - "Status code 100"
                type: str
            status_101:
                description:
                - "Status code 101"
                type: str
            status_102:
                description:
                - "Status code 102"
                type: str
            status_300:
                description:
                - "Status code 300"
                type: str
            status_301:
                description:
                - "Status code 301"
                type: str
            status_302:
                description:
                - "Status code 302"
                type: str
            status_303:
                description:
                - "Status code 303"
                type: str
            status_304:
                description:
                - "Status code 304"
                type: str
            status_305:
                description:
                - "Status code 305"
                type: str
            status_306:
                description:
                - "Status code 306"
                type: str
            status_307:
                description:
                - "Status code 307"
                type: str
            status_400:
                description:
                - "Status code 400"
                type: str
            status_401:
                description:
                - "Status code 401"
                type: str
            status_402:
                description:
                - "Status code 402"
                type: str
            status_403:
                description:
                - "Status code 403"
                type: str
            status_404:
                description:
                - "Status code 404"
                type: str
            status_405:
                description:
                - "Status code 405"
                type: str
            status_406:
                description:
                - "Status code 406"
                type: str
            status_407:
                description:
                - "Status code 407"
                type: str
            status_408:
                description:
                - "Status code 408"
                type: str
            status_409:
                description:
                - "Status code 409"
                type: str
            status_410:
                description:
                - "Status code 410"
                type: str
            status_411:
                description:
                - "Status code 411"
                type: str
            status_412:
                description:
                - "Status code 412"
                type: str
            status_413:
                description:
                - "Status code 413"
                type: str
            status_414:
                description:
                - "Status code 414"
                type: str
            status_415:
                description:
                - "Status code 415"
                type: str
            status_416:
                description:
                - "Status code 416"
                type: str
            status_417:
                description:
                - "Status code 417"
                type: str
            status_418:
                description:
                - "Status code 418"
                type: str
            status_422:
                description:
                - "Status code 422"
                type: str
            status_423:
                description:
                - "Status code 423"
                type: str
            status_424:
                description:
                - "Status code 424"
                type: str
            status_425:
                description:
                - "Status code 425"
                type: str
            status_426:
                description:
                - "Status code 426"
                type: str
            status_449:
                description:
                - "Status code 449"
                type: str
            status_450:
                description:
                - "Status code 450"
                type: str
            status_500:
                description:
                - "Status code 500"
                type: str
            status_501:
                description:
                - "Status code 501"
                type: str
            status_502:
                description:
                - "Status code 502"
                type: str
            status_503:
                description:
                - "Status code 503"
                type: str
            status_504:
                description:
                - "Status code 504"
                type: str
            status_505:
                description:
                - "Status code 505"
                type: str
            status_506:
                description:
                - "Status code 506"
                type: str
            status_507:
                description:
                - "Status code 507"
                type: str
            status_508:
                description:
                - "Status code 508"
                type: str
            status_509:
                description:
                - "Status code 509"
                type: str
            status_510:
                description:
                - "Status code 510"
                type: str
            status_1xx:
                description:
                - "status code 1XX"
                type: str
            status_2xx:
                description:
                - "status code 2XX"
                type: str
            status_3xx:
                description:
                - "status code 3XX"
                type: str
            status_4xx:
                description:
                - "status code 4XX"
                type: str
            status_5xx:
                description:
                - "status code 5XX"
                type: str
            status_6xx:
                description:
                - "status code 6XX"
                type: str
            status_unknown:
                description:
                - "Status code unknown"
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

# standard ansible module imports
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
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


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
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'status_200', 'status_201', 'status_202', 'status_203', 'status_204', 'status_205', 'status_206', 'status_207', 'status_100', 'status_101', 'status_102', 'status_300', 'status_301', 'status_302', 'status_303', 'status_304', 'status_305', 'status_306', 'status_307', 'status_400', 'status_401', 'status_402', 'status_403', 'status_404', 'status_405', 'status_406', 'status_407', 'status_408', 'status_409', 'status_410', 'status_411', 'status_412', 'status_413', 'status_414', 'status_415', 'status_416', 'status_417', 'status_418', 'status_422', 'status_423', 'status_424', 'status_425', 'status_426', 'status_449', 'status_450', 'status_500', 'status_501', 'status_502', 'status_503', 'status_504', 'status_505', 'status_506', 'status_507', 'status_508', 'status_509', 'status_510', 'status_1xx', 'status_2xx', 'status_3xx', 'status_4xx', 'status_5xx', 'status_6xx', 'status_unknown']}},
        'oper': {'type': 'dict', 'l4_cpu_list': {'type': 'list', 'status_2xx': {'type': 'int', }, 'status_200': {'type': 'int', }, 'status_201': {'type': 'int', }, 'status_202': {'type': 'int', }, 'status_203': {'type': 'int', }, 'status_204': {'type': 'int', }, 'status_205': {'type': 'int', }, 'status_206': {'type': 'int', }, 'status_207': {'type': 'int', }, 'status_1xx': {'type': 'int', }, 'status_100': {'type': 'int', }, 'status_101': {'type': 'int', }, 'status_102': {'type': 'int', }, 'status_3xx': {'type': 'int', }, 'status_300': {'type': 'int', }, 'status_301': {'type': 'int', }, 'status_302': {'type': 'int', }, 'status_303': {'type': 'int', }, 'status_304': {'type': 'int', }, 'status_305': {'type': 'int', }, 'status_306': {'type': 'int', }, 'status_307': {'type': 'int', }, 'status_4xx': {'type': 'int', }, 'status_400': {'type': 'int', }, 'status_401': {'type': 'int', }, 'status_402': {'type': 'int', }, 'status_403': {'type': 'int', }, 'status_404': {'type': 'int', }, 'status_405': {'type': 'int', }, 'status_406': {'type': 'int', }, 'status_407': {'type': 'int', }, 'status_408': {'type': 'int', }, 'status_409': {'type': 'int', }, 'status_410': {'type': 'int', }, 'status_411': {'type': 'int', }, 'status_412': {'type': 'int', }, 'status_413': {'type': 'int', }, 'status_414': {'type': 'int', }, 'status_415': {'type': 'int', }, 'status_416': {'type': 'int', }, 'status_417': {'type': 'int', }, 'status_418': {'type': 'int', }, 'status_422': {'type': 'int', }, 'status_423': {'type': 'int', }, 'status_424': {'type': 'int', }, 'status_425': {'type': 'int', }, 'status_426': {'type': 'int', }, 'status_449': {'type': 'int', }, 'status_450': {'type': 'int', }, 'status_5xx': {'type': 'int', }, 'status_500': {'type': 'int', }, 'status_501': {'type': 'int', }, 'status_502': {'type': 'int', }, 'status_503': {'type': 'int', }, 'status_504': {'type': 'int', }, 'status_505': {'type': 'int', }, 'status_506': {'type': 'int', }, 'status_507': {'type': 'int', }, 'status_508': {'type': 'int', }, 'status_509': {'type': 'int', }, 'status_510': {'type': 'int', }, 'status_6xx': {'type': 'int', }}, 'cpu_count': {'type': 'int', }},
        'stats': {'type': 'dict', 'status_200': {'type': 'str', }, 'status_201': {'type': 'str', }, 'status_202': {'type': 'str', }, 'status_203': {'type': 'str', }, 'status_204': {'type': 'str', }, 'status_205': {'type': 'str', }, 'status_206': {'type': 'str', }, 'status_207': {'type': 'str', }, 'status_100': {'type': 'str', }, 'status_101': {'type': 'str', }, 'status_102': {'type': 'str', }, 'status_300': {'type': 'str', }, 'status_301': {'type': 'str', }, 'status_302': {'type': 'str', }, 'status_303': {'type': 'str', }, 'status_304': {'type': 'str', }, 'status_305': {'type': 'str', }, 'status_306': {'type': 'str', }, 'status_307': {'type': 'str', }, 'status_400': {'type': 'str', }, 'status_401': {'type': 'str', }, 'status_402': {'type': 'str', }, 'status_403': {'type': 'str', }, 'status_404': {'type': 'str', }, 'status_405': {'type': 'str', }, 'status_406': {'type': 'str', }, 'status_407': {'type': 'str', }, 'status_408': {'type': 'str', }, 'status_409': {'type': 'str', }, 'status_410': {'type': 'str', }, 'status_411': {'type': 'str', }, 'status_412': {'type': 'str', }, 'status_413': {'type': 'str', }, 'status_414': {'type': 'str', }, 'status_415': {'type': 'str', }, 'status_416': {'type': 'str', }, 'status_417': {'type': 'str', }, 'status_418': {'type': 'str', }, 'status_422': {'type': 'str', }, 'status_423': {'type': 'str', }, 'status_424': {'type': 'str', }, 'status_425': {'type': 'str', }, 'status_426': {'type': 'str', }, 'status_449': {'type': 'str', }, 'status_450': {'type': 'str', }, 'status_500': {'type': 'str', }, 'status_501': {'type': 'str', }, 'status_502': {'type': 'str', }, 'status_503': {'type': 'str', }, 'status_504': {'type': 'str', }, 'status_505': {'type': 'str', }, 'status_506': {'type': 'str', }, 'status_507': {'type': 'str', }, 'status_508': {'type': 'str', }, 'status_509': {'type': 'str', }, 'status_510': {'type': 'str', }, 'status_1xx': {'type': 'str', }, 'status_2xx': {'type': 'str', }, 'status_3xx': {'type': 'str', }, 'status_4xx': {'type': 'str', }, 'status_5xx': {'type': 'str', }, 'status_6xx': {'type': 'str', }, 'status_unknown': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/icap_http"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/icap_http"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["icap_http"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["icap_http"].get(k) != v:
            change_results["changed"] = True
            config_changes["icap_http"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("icap_http", module.params, AVAILABLE_PROPERTIES)
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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
