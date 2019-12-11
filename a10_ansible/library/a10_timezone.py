#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_timezone
description:
    - Configure the Time Zone
short_description: Configures A10 timezone
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            dst_name:
                description:
                - "Field dst_name"
            deny_dst:
                description:
                - "Field deny_dst"
            std_name:
                description:
                - "Field std_name"
            location:
                description:
                - "Field location"
    timezone_index_cfg:
        description:
        - "Field timezone_index_cfg"
        required: False
        suboptions:
            timezone_index:
                description:
                - "'UTC'= Coordinated Universal Time (UTC); 'Pacific/Midway'= (GMT-11=00)Midway Island, Samoa; 'Pacific/Honolulu'= (GMT-10=00)Hawaii; 'America/Anchorage'= (GMT-09=00)Alaska; 'America/Tijuana'= (GMT-08=00)Pacific Time - Tijuana; 'America/Los_Angeles'= (GMT-08=00)Pacific Time(US & Canada); 'America/Vancouver'= (GMT-08=00)Pacific Time - west British Columbia; 'America/Phoenix'= (GMT-07=00)Arizona; 'America/Shiprock'= (GMT-07=00)Mountain Time(US & Canada); 'America/Chicago'= (GMT-06=00)Central Time(US & Canada); 'America/Mexico_City'= (GMT-06=00)Mexico City; 'America/Regina'= (GMT-06=00)Saskatchewan; 'America/Swift_Current'= (GMT-06=00)Central America; 'America/Kentucky/Monticello'= (GMT-05=00)Eastern Time(US & Canada); 'America/Indiana/Marengo'= (GMT-05=00)Indiana(East); 'America/Montreal'= (GMT-05=00)Eastern Time - Ontario & Quebec - most locations; 'America/New_York'= (GMT-05=00)Eastern Time; 'America/Toronto'= (GMT-05=00)Eastern Time - Toronto, Ontario; 'America/Caracas'= (GMT-04=00)Caracas, La Paz; 'America/Halifax'= (GMT-04=00)Atlantic Time(Canada); 'America/Santiago'= (GMT-04=00)Santiago; 'America/St_Johns'= (GMT-03=30)Newfoundland; 'America/Buenos_Aires'= (GMT-03=00)Buenos Aires, Georgetown; 'America/Godthab'= (GMT-03=00)Greenland; 'America/Brasilia'= (GMT-03=00)Brasilia; 'Atlantic/South_Georgia'= (GMT-02=00)Mid-Atlantic; 'Atlantic/Azores'= (GMT-01=00)Azores; 'Atlantic/Cape_Verde'= (GMT-01=00)Cape Verde Is.; 'Europe/Dublin'= (GMT)Greenwich Mean Time= Dublin, Edinburgh, Lisbon, London; 'Africa/Algiers'= (GMT+01=00)West Central Africa; 'Europe/Amsterdam'= (GMT+01=00)Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna; 'Europe/Belgrade'= (GMT+01=00)Belgrade, Bratislava, Budapest, Ljubljana, Prague; 'Europe/Brussels'= (GMT+01=00)Brussels, Copenhagen, Madrid, Paris; 'Europe/Sarajevo'= (GMT+01=00)Sarajevo, Skopje, Sofija, Vilnius, Warsaw, Zagreb; 'Europe/Bucharest'= (GMT+02=00)Bucharest; 'Africa/Cairo'= (GMT+02=00)Cairo; 'Europe/Athens'= (GMT+02=00)Athens, Istanbul, Minsk; 'Africa/Harare'= (GMT+02=00)Harare, Pretoria; 'Asia/Jerusalem'= (GMT+02=00)Jerusalem; 'Europe/Helsinki'= (GMT+02=00)Helsinki, Riga, Tallinn; 'Africa/Nairobi'= (GMT+03=00)Nairobi; 'Asia/Baghdad'= (GMT+03=00)Baghdad; 'Asia/Kuwait'= (GMT+03=00)Kuwait, Riyadh; 'Europe/Moscow'= (GMT+03=00)Moscow, St.Petersburg, Volgogard; 'Asia/Tehran'= (GMT+03=30)Tehran; 'Asia/Baku'= (GMT+04=00)Baku, Tbilisi, Yerevan; 'Asia/Muscat'= (GMT+04=00)Abu Dhabi, Muscat; 'Asia/Kabul'= (GMT+04=30)Kabul; 'Asia/Karachi'= (GMT+05=00)Islamabad, Karachi, Tashkent; 'Asia/Yekaterinburg'= (GMT+05=00)Ekaterinburg; 'Asia/Calcutta'= (GMT+05=30)Calcutta, Chennai, Mumbai, New Delhi; 'Asia/Katmandu'= (GMT+05=45)Kathmandu; 'Asia/Almaty'= (GMT+06=00)Almaty, Novosibirsk; 'Asia/Dhaka'= (GMT+06=00)Astana, Dhaka; 'Indian/Chagos'= (GMT+06=00)Sri Jayawardenepura; 'Asia/Rangoon'= (GMT+06=30)Rangoon; 'Asia/Bangkok'= (GMT+07=00)Bangkok, Hanoi, Jakarta; 'Asia/Krasnoyarsk'= (GMT+07=00)Krasnoyarsk; 'Asia/Irkutsk'= (GMT+08=00)Irkutsk, Ulaan Bataar; 'Asia/Kuala_Lumpur'= (GMT+08=00)Kuala Lumpur, Singapore; 'Asia/Shanghai'= (GMT+08=00)Beijing, Chongqing, Hong Kong, Urumqi; 'Asia/Taipei'= (GMT+08=00)Taipei; 'Australia/Perth'= (GMT+08=00)Perth; 'Asia/Seoul'= (GMT+09=00)Seoul; 'Asia/Tokyo'= (GMT+09=00)Osaka, Sapporo, Tokyo; 'Asia/Yakutsk'= (GMT+09=00)Yakutsk; 'Australia/Adelaide'= (GMT+09=30)Adelaide; 'Australia/Darwin'= (GMT+09=30)Darwin; 'Australia/Hobart'= (GMT+10=00)Hobart; 'Australia/Brisbane'= (GMT+10=00)Brisbane; 'Asia/Vladivostok'= (GMT+10=00)Vladivostok; 'Australia/Sydney'= (GMT+10=00)Canberra, Melbourne, Sydney; 'Pacific/Guam'= (GMT+10=00)Guam, Port Moresby; 'Asia/Magadan'= (GMT+11=00)Magadan, Solomon., New Caledonia; 'Pacific/Auckland'= (GMT+12=00)Auckland, Wellington; 'Pacific/Fiji'= (GMT+12=00)Fiji, Kamchatka, Marshall Is.; 'Pacific/Kwajalein'= (GMT+12=00)Eniwetok, Kwajalein; 'Pacific/Enderbury'= (GMT+13=00)Nuku'alofa; "
            nodst:
                description:
                - "Disable daylight saving time"
    uuid:
        description:
        - "uuid of the object"
        required: False

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["oper","timezone_index_cfg","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',dst_name=dict(type='str',),deny_dst=dict(type='str',),std_name=dict(type='str',),location=dict(type='str',)),
        timezone_index_cfg=dict(type='dict',timezone_index=dict(type='str',choices=['UTC','Pacific/Midway','Pacific/Honolulu','America/Anchorage','America/Tijuana','America/Los_Angeles','America/Vancouver','America/Phoenix','America/Shiprock','America/Chicago','America/Mexico_City','America/Regina','America/Swift_Current','America/Kentucky/Monticello','America/Indiana/Marengo','America/Montreal','America/New_York','America/Toronto','America/Caracas','America/Halifax','America/Santiago','America/St_Johns','America/Buenos_Aires','America/Godthab','America/Brasilia','Atlantic/South_Georgia','Atlantic/Azores','Atlantic/Cape_Verde','Europe/Dublin','Africa/Algiers','Europe/Amsterdam','Europe/Belgrade','Europe/Brussels','Europe/Sarajevo','Europe/Bucharest','Africa/Cairo','Europe/Athens','Africa/Harare','Asia/Jerusalem','Europe/Helsinki','Africa/Nairobi','Asia/Baghdad','Asia/Kuwait','Europe/Moscow','Asia/Tehran','Asia/Baku','Asia/Muscat','Asia/Kabul','Asia/Karachi','Asia/Yekaterinburg','Asia/Calcutta','Asia/Katmandu','Asia/Almaty','Asia/Dhaka','Indian/Chagos','Asia/Rangoon','Asia/Bangkok','Asia/Krasnoyarsk','Asia/Irkutsk','Asia/Kuala_Lumpur','Asia/Shanghai','Asia/Taipei','Australia/Perth','Asia/Seoul','Asia/Tokyo','Asia/Yakutsk','Australia/Adelaide','Australia/Darwin','Australia/Hobart','Australia/Brisbane','Asia/Vladivostok','Australia/Sydney','Pacific/Guam','Asia/Magadan','Pacific/Auckland','Pacific/Fiji','Pacific/Kwajalein','Pacific/Enderbury']),nodst=dict(type='bool',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/timezone"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/timezone"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["timezone"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["timezone"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["timezone"][k] = v
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
    payload = build_json("timezone", module)
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()