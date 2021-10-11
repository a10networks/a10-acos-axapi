#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_timezone
description:
    - Configure the Time Zone
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
    timezone_index_cfg:
        description:
        - "Field timezone_index_cfg"
        type: dict
        required: False
        suboptions:
            timezone_index:
                description:
                - "'UTC'= Coordinated Universal Time (UTC); 'Pacific/Midway'= (GMT-11=00)Midway
          Island, Samoa; 'Pacific/Honolulu'= (GMT-10=00)Hawaii; 'America/Anchorage'=
          (GMT-09=00)Alaska; 'America/Tijuana'= (GMT-08=00)Pacific Time - Tijuana;
          'America/Los_Angeles'= (GMT-08=00)Pacific Time(US & Canada);
          'America/Vancouver'= (GMT-08=00)Pacific Time - west British Columbia;
          'America/Phoenix'= (GMT-07=00)Arizona; 'America/Shiprock'= (GMT-07=00)Mountain
          Time(US & Canada); 'America/Chicago'= (GMT-06=00)Central Time(US & Canada);
          'America/Mexico_City'= (GMT-06=00)Mexico City; 'America/Regina'=
          (GMT-06=00)Saskatchewan; 'America/Swift_Current'= (GMT-06=00)Central America;
          'America/Kentucky/Monticello'= (GMT-05=00)Eastern Time(US & Canada);
          'America/Indiana/Marengo'= (GMT-05=00)Indiana(East); 'America/Montreal'=
          (GMT-05=00)Eastern Time - Ontario & Quebec - most locations;
          'America/New_York'= (GMT-05=00)Eastern Time; 'America/Toronto'=
          (GMT-05=00)Eastern Time - Toronto, Ontario; 'America/Caracas'=
          (GMT-04=00)Caracas, La Paz; 'America/Halifax'= (GMT-04=00)Atlantic
          Time(Canada); 'America/Santiago'= (GMT-04=00)Santiago; 'America/St_Johns'=
          (GMT-03=30)Newfoundland; 'America/Buenos_Aires'= (GMT-03=00)Buenos Aires,
          Georgetown; 'America/Godthab'= (GMT-03=00)Greenland; 'America/Brasilia'=
          (GMT-03=00)Brasilia; 'Atlantic/South_Georgia'= (GMT-02=00)Mid-Atlantic;
          'Atlantic/Azores'= (GMT-01=00)Azores; 'Atlantic/Cape_Verde'= (GMT-01=00)Cape
          Verde Is.; 'Europe/Dublin'= (GMT)Greenwich Mean Time= Dublin, Edinburgh,
          Lisbon, London; 'Africa/Algiers'= (GMT+01=00)West Central Africa;
          'Europe/Amsterdam'= (GMT+01=00)Amsterdam, Berlin, Bern, Rome, Stockholm,
          Vienna; 'Europe/Belgrade'= (GMT+01=00)Belgrade, Bratislava, Budapest,
          Ljubljana, Prague; 'Europe/Brussels'= (GMT+01=00)Brussels, Copenhagen, Madrid,
          Paris; 'Europe/Sarajevo'= (GMT+01=00)Sarajevo, Skopje, Sofija, Vilnius, Warsaw,
          Zagreb; 'Europe/Bucharest'= (GMT+02=00)Bucharest; 'Africa/Cairo'=
          (GMT+02=00)Cairo; 'Europe/Athens'= (GMT+02=00)Athens, Istanbul, Minsk;
          'Africa/Harare'= (GMT+02=00)Harare, Pretoria; 'Asia/Jerusalem'=
          (GMT+02=00)Jerusalem; 'Europe/Helsinki'= (GMT+02=00)Helsinki, Riga, Tallinn;
          'Africa/Nairobi'= (GMT+03=00)Nairobi; 'Asia/Baghdad'= (GMT+03=00)Baghdad;
          'Asia/Kuwait'= (GMT+03=00)Kuwait, Riyadh; 'Europe/Moscow'= (GMT+03=00)Moscow,
          St.Petersburg, Volgogard; 'Asia/Tehran'= (GMT+03=30)Tehran; 'Asia/Baku'=
          (GMT+04=00)Baku, Tbilisi, Yerevan; 'Asia/Muscat'= (GMT+04=00)Abu Dhabi, Muscat;
          'Asia/Kabul'= (GMT+04=30)Kabul; 'Asia/Karachi'= (GMT+05=00)Islamabad, Karachi,
          Tashkent; 'Asia/Yekaterinburg'= (GMT+05=00)Ekaterinburg; 'Asia/Calcutta'=
          (GMT+05=30)Calcutta, Chennai, Mumbai, New Delhi; 'Asia/Katmandu'=
          (GMT+05=45)Kathmandu; 'Asia/Almaty'= (GMT+06=00)Almaty, Novosibirsk;
          'Asia/Dhaka'= (GMT+06=00)Astana, Dhaka; 'Indian/Chagos'= (GMT+06=00)Sri
          Jayawardenepura; 'Asia/Rangoon'= (GMT+06=30)Rangoon; 'Asia/Bangkok'=
          (GMT+07=00)Bangkok, Hanoi, Jakarta; 'Asia/Krasnoyarsk'= (GMT+07=00)Krasnoyarsk;
          'Asia/Irkutsk'= (GMT+08=00)Irkutsk, Ulaan Bataar; 'Asia/Kuala_Lumpur'=
          (GMT+08=00)Kuala Lumpur, Singapore; 'Asia/Shanghai'= (GMT+08=00)Beijing,
          Chongqing, Hong Kong, Urumqi; 'Asia/Taipei'= (GMT+08=00)Taipei;
          'Australia/Perth'= (GMT+08=00)Perth; 'Asia/Seoul'= (GMT+09=00)Seoul;
          'Asia/Tokyo'= (GMT+09=00)Osaka, Sapporo, Tokyo; 'Asia/Yakutsk'=
          (GMT+09=00)Yakutsk; 'Australia/Adelaide'= (GMT+09=30)Adelaide;
          'Australia/Darwin'= (GMT+09=30)Darwin; 'Australia/Hobart'= (GMT+10=00)Hobart;
          'Australia/Brisbane'= (GMT+10=00)Brisbane; 'Asia/Vladivostok'=
          (GMT+10=00)Vladivostok; 'Australia/Sydney'= (GMT+10=00)Canberra, Melbourne,
          Sydney; 'Pacific/Guam'= (GMT+10=00)Guam, Port Moresby; 'Asia/Magadan'=
          (GMT+11=00)Magadan, Solomon., New Caledonia; 'Pacific/Auckland'=
          (GMT+12=00)Auckland, Wellington; 'Pacific/Fiji'= (GMT+12=00)Fiji, Kamchatka,
          Marshall Is.; 'Pacific/Kwajalein'= (GMT+12=00)Eniwetok, Kwajalein;
          'Pacific/Enderbury'= (GMT+13=00)Nuku'alofa;"
                type: str
            nodst:
                description:
                - "Disable daylight saving time"
                type: bool
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            std_name:
                description:
                - "Field std_name"
                type: str
            dst_name:
                description:
                - "Field dst_name"
                type: str
            deny_dst:
                description:
                - "Field deny_dst"
                type: str
            location:
                description:
                - "Field location"
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
AVAILABLE_PROPERTIES = [
    "oper",
    "timezone_index_cfg",
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
        'timezone_index_cfg': {
            'type': 'dict',
            'timezone_index': {
                'type':
                'str',
                'choices': [
                    'UTC', 'Pacific/Midway', 'Pacific/Honolulu',
                    'America/Anchorage', 'America/Tijuana',
                    'America/Los_Angeles', 'America/Vancouver',
                    'America/Phoenix', 'America/Shiprock', 'America/Chicago',
                    'America/Mexico_City', 'America/Regina',
                    'America/Swift_Current', 'America/Kentucky/Monticello',
                    'America/Indiana/Marengo', 'America/Montreal',
                    'America/New_York', 'America/Toronto', 'America/Caracas',
                    'America/Halifax', 'America/Santiago', 'America/St_Johns',
                    'America/Buenos_Aires', 'America/Godthab',
                    'America/Brasilia', 'Atlantic/South_Georgia',
                    'Atlantic/Azores', 'Atlantic/Cape_Verde', 'Europe/Dublin',
                    'Africa/Algiers', 'Europe/Amsterdam', 'Europe/Belgrade',
                    'Europe/Brussels', 'Europe/Sarajevo', 'Europe/Bucharest',
                    'Africa/Cairo', 'Europe/Athens', 'Africa/Harare',
                    'Asia/Jerusalem', 'Europe/Helsinki', 'Africa/Nairobi',
                    'Asia/Baghdad', 'Asia/Kuwait', 'Europe/Moscow',
                    'Asia/Tehran', 'Asia/Baku', 'Asia/Muscat', 'Asia/Kabul',
                    'Asia/Karachi', 'Asia/Yekaterinburg', 'Asia/Calcutta',
                    'Asia/Katmandu', 'Asia/Almaty', 'Asia/Dhaka',
                    'Indian/Chagos', 'Asia/Rangoon', 'Asia/Bangkok',
                    'Asia/Krasnoyarsk', 'Asia/Irkutsk', 'Asia/Kuala_Lumpur',
                    'Asia/Shanghai', 'Asia/Taipei', 'Australia/Perth',
                    'Asia/Seoul', 'Asia/Tokyo', 'Asia/Yakutsk',
                    'Australia/Adelaide', 'Australia/Darwin',
                    'Australia/Hobart', 'Australia/Brisbane',
                    'Asia/Vladivostok', 'Australia/Sydney', 'Pacific/Guam',
                    'Asia/Magadan', 'Pacific/Auckland', 'Pacific/Fiji',
                    'Pacific/Kwajalein', 'Pacific/Enderbury'
                ]
            },
            'nodst': {
                'type': 'bool',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'oper': {
            'type': 'dict',
            'std_name': {
                'type': 'str',
            },
            'dst_name': {
                'type': 'str',
            },
            'deny_dst': {
                'type': 'str',
            },
            'location': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/timezone"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/timezone"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["timezone"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["timezone"].get(k) != v:
            change_results["changed"] = True
            config_changes["timezone"][k] = v

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
    payload = utils.build_json("timezone", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "timezone"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "timezone-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["timezone"][
                    "oper"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
