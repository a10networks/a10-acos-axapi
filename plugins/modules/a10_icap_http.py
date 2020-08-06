#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_icap_http
description:
    - Configure ICAP
short_description: Configures A10 icap_http
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
            cpu_count:
                description:
                - "Field cpu_count"
    sampling_enable:
        description:
        - "Field sampling_enable"
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            status_503:
                description:
                - "Status code 503"
            status_306:
                description:
                - "Status code 306"
            status_500:
                description:
                - "Status code 500"
            status_307:
                description:
                - "Status code 307"
            status_1xx:
                description:
                - "status code 1XX"
            status_450:
                description:
                - "Status code 450"
            status_412:
                description:
                - "Status code 412"
            status_413:
                description:
                - "Status code 413"
            status_410:
                description:
                - "Status code 410"
            status_411:
                description:
                - "Status code 411"
            status_416:
                description:
                - "Status code 416"
            status_417:
                description:
                - "Status code 417"
            status_414:
                description:
                - "Status code 414"
            status_415:
                description:
                - "Status code 415"
            status_418:
                description:
                - "Status code 418"
            status_unknown:
                description:
                - "Status code unknown"
            status_100:
                description:
                - "Status code 100"
            status_101:
                description:
                - "Status code 101"
            status_102:
                description:
                - "Status code 102"
            status_510:
                description:
                - "Status code 510"
            status_303:
                description:
                - "Status code 303"
            status_300:
                description:
                - "Status code 300"
            status_301:
                description:
                - "Status code 301"
            status_401:
                description:
                - "Status code 401"
            status_400:
                description:
                - "Status code 400"
            status_207:
                description:
                - "Status code 207"
            status_206:
                description:
                - "Status code 206"
            status_205:
                description:
                - "Status code 205"
            status_204:
                description:
                - "Status code 204"
            status_203:
                description:
                - "Status code 203"
            status_202:
                description:
                - "Status code 202"
            status_201:
                description:
                - "Status code 201"
            status_200:
                description:
                - "Status code 200"
            status_423:
                description:
                - "Status code 423"
            status_422:
                description:
                - "Status code 422"
            status_304:
                description:
                - "Status code 304"
            status_305:
                description:
                - "Status code 305"
            status_302:
                description:
                - "Status code 302"
            status_426:
                description:
                - "Status code 426"
            status_425:
                description:
                - "Status code 425"
            status_424:
                description:
                - "Status code 424"
            status_508:
                description:
                - "Status code 508"
            status_509:
                description:
                - "Status code 509"
            status_403:
                description:
                - "Status code 403"
            status_402:
                description:
                - "Status code 402"
            status_405:
                description:
                - "Status code 405"
            status_404:
                description:
                - "Status code 404"
            status_407:
                description:
                - "Status code 407"
            status_2xx:
                description:
                - "status code 2XX"
            status_409:
                description:
                - "Status code 409"
            status_408:
                description:
                - "Status code 408"
            status_502:
                description:
                - "Status code 502"
            status_406:
                description:
                - "Status code 406"
            status_504:
                description:
                - "Status code 504"
            status_505:
                description:
                - "Status code 505"
            status_506:
                description:
                - "Status code 506"
            status_507:
                description:
                - "Status code 507"
            status_4xx:
                description:
                - "status code 4XX"
            status_6xx:
                description:
                - "status code 6XX"
            status_501:
                description:
                - "Status code 501"
            status_449:
                description:
                - "Status code 449"
            status_5xx:
                description:
                - "status code 5XX"
            status_3xx:
                description:
                - "status code 3XX"
    uuid:
        description:
        - "uuid of the object"
        required: False

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
    "oper",
    "sampling_enable",
    "stats",
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
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'status_306': {
                    'type': 'int',
                },
                'status_307': {
                    'type': 'int',
                },
                'status_1xx': {
                    'type': 'int',
                },
                'status_450': {
                    'type': 'int',
                },
                'status_412': {
                    'type': 'int',
                },
                'status_413': {
                    'type': 'int',
                },
                'status_410': {
                    'type': 'int',
                },
                'status_411': {
                    'type': 'int',
                },
                'status_416': {
                    'type': 'int',
                },
                'status_417': {
                    'type': 'int',
                },
                'status_414': {
                    'type': 'int',
                },
                'status_415': {
                    'type': 'int',
                },
                'status_418': {
                    'type': 'int',
                },
                'status_6xx': {
                    'type': 'int',
                },
                'status_100': {
                    'type': 'int',
                },
                'status_101': {
                    'type': 'int',
                },
                'status_102': {
                    'type': 'int',
                },
                'status_510': {
                    'type': 'int',
                },
                'status_303': {
                    'type': 'int',
                },
                'status_300': {
                    'type': 'int',
                },
                'status_301': {
                    'type': 'int',
                },
                'status_401': {
                    'type': 'int',
                },
                'status_400': {
                    'type': 'int',
                },
                'status_4xx': {
                    'type': 'int',
                },
                'status_207': {
                    'type': 'int',
                },
                'status_206': {
                    'type': 'int',
                },
                'status_205': {
                    'type': 'int',
                },
                'status_204': {
                    'type': 'int',
                },
                'status_203': {
                    'type': 'int',
                },
                'status_202': {
                    'type': 'int',
                },
                'status_201': {
                    'type': 'int',
                },
                'status_200': {
                    'type': 'int',
                },
                'status_423': {
                    'type': 'int',
                },
                'status_422': {
                    'type': 'int',
                },
                'status_304': {
                    'type': 'int',
                },
                'status_305': {
                    'type': 'int',
                },
                'status_302': {
                    'type': 'int',
                },
                'status_426': {
                    'type': 'int',
                },
                'status_425': {
                    'type': 'int',
                },
                'status_424': {
                    'type': 'int',
                },
                'status_508': {
                    'type': 'int',
                },
                'status_509': {
                    'type': 'int',
                },
                'status_403': {
                    'type': 'int',
                },
                'status_402': {
                    'type': 'int',
                },
                'status_405': {
                    'type': 'int',
                },
                'status_404': {
                    'type': 'int',
                },
                'status_407': {
                    'type': 'int',
                },
                'status_2xx': {
                    'type': 'int',
                },
                'status_500': {
                    'type': 'int',
                },
                'status_408': {
                    'type': 'int',
                },
                'status_502': {
                    'type': 'int',
                },
                'status_503': {
                    'type': 'int',
                },
                'status_504': {
                    'type': 'int',
                },
                'status_505': {
                    'type': 'int',
                },
                'status_506': {
                    'type': 'int',
                },
                'status_507': {
                    'type': 'int',
                },
                'status_409': {
                    'type': 'int',
                },
                'status_406': {
                    'type': 'int',
                },
                'status_501': {
                    'type': 'int',
                },
                'status_449': {
                    'type': 'int',
                },
                'status_5xx': {
                    'type': 'int',
                },
                'status_3xx': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'status_200', 'status_201', 'status_202',
                    'status_203', 'status_204', 'status_205', 'status_206',
                    'status_207', 'status_100', 'status_101', 'status_102',
                    'status_300', 'status_301', 'status_302', 'status_303',
                    'status_304', 'status_305', 'status_306', 'status_307',
                    'status_400', 'status_401', 'status_402', 'status_403',
                    'status_404', 'status_405', 'status_406', 'status_407',
                    'status_408', 'status_409', 'status_410', 'status_411',
                    'status_412', 'status_413', 'status_414', 'status_415',
                    'status_416', 'status_417', 'status_418', 'status_422',
                    'status_423', 'status_424', 'status_425', 'status_426',
                    'status_449', 'status_450', 'status_500', 'status_501',
                    'status_502', 'status_503', 'status_504', 'status_505',
                    'status_506', 'status_507', 'status_508', 'status_509',
                    'status_510', 'status_1xx', 'status_2xx', 'status_3xx',
                    'status_4xx', 'status_5xx', 'status_6xx', 'status_unknown'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'status_503': {
                'type': 'str',
            },
            'status_306': {
                'type': 'str',
            },
            'status_500': {
                'type': 'str',
            },
            'status_307': {
                'type': 'str',
            },
            'status_1xx': {
                'type': 'str',
            },
            'status_450': {
                'type': 'str',
            },
            'status_412': {
                'type': 'str',
            },
            'status_413': {
                'type': 'str',
            },
            'status_410': {
                'type': 'str',
            },
            'status_411': {
                'type': 'str',
            },
            'status_416': {
                'type': 'str',
            },
            'status_417': {
                'type': 'str',
            },
            'status_414': {
                'type': 'str',
            },
            'status_415': {
                'type': 'str',
            },
            'status_418': {
                'type': 'str',
            },
            'status_unknown': {
                'type': 'str',
            },
            'status_100': {
                'type': 'str',
            },
            'status_101': {
                'type': 'str',
            },
            'status_102': {
                'type': 'str',
            },
            'status_510': {
                'type': 'str',
            },
            'status_303': {
                'type': 'str',
            },
            'status_300': {
                'type': 'str',
            },
            'status_301': {
                'type': 'str',
            },
            'status_401': {
                'type': 'str',
            },
            'status_400': {
                'type': 'str',
            },
            'status_207': {
                'type': 'str',
            },
            'status_206': {
                'type': 'str',
            },
            'status_205': {
                'type': 'str',
            },
            'status_204': {
                'type': 'str',
            },
            'status_203': {
                'type': 'str',
            },
            'status_202': {
                'type': 'str',
            },
            'status_201': {
                'type': 'str',
            },
            'status_200': {
                'type': 'str',
            },
            'status_423': {
                'type': 'str',
            },
            'status_422': {
                'type': 'str',
            },
            'status_304': {
                'type': 'str',
            },
            'status_305': {
                'type': 'str',
            },
            'status_302': {
                'type': 'str',
            },
            'status_426': {
                'type': 'str',
            },
            'status_425': {
                'type': 'str',
            },
            'status_424': {
                'type': 'str',
            },
            'status_508': {
                'type': 'str',
            },
            'status_509': {
                'type': 'str',
            },
            'status_403': {
                'type': 'str',
            },
            'status_402': {
                'type': 'str',
            },
            'status_405': {
                'type': 'str',
            },
            'status_404': {
                'type': 'str',
            },
            'status_407': {
                'type': 'str',
            },
            'status_2xx': {
                'type': 'str',
            },
            'status_409': {
                'type': 'str',
            },
            'status_408': {
                'type': 'str',
            },
            'status_502': {
                'type': 'str',
            },
            'status_406': {
                'type': 'str',
            },
            'status_504': {
                'type': 'str',
            },
            'status_505': {
                'type': 'str',
            },
            'status_506': {
                'type': 'str',
            },
            'status_507': {
                'type': 'str',
            },
            'status_4xx': {
                'type': 'str',
            },
            'status_6xx': {
                'type': 'str',
            },
            'status_501': {
                'type': 'str',
            },
            'status_449': {
                'type': 'str',
            },
            'status_5xx': {
                'type': 'str',
            },
            'status_3xx': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/icap_http"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/slb/icap_http"

    f_dict = {}

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
        for k, v in payload["icap_http"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["icap_http"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["icap_http"][k] = v
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
    payload = build_json("icap_http", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
