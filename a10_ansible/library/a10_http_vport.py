#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_http_vport
description:
    - http vport counters
short_description: Configures A10 http_vport
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'status_200'= Status code 200; 'status_201'= Status code 201; 'status_202'= Status code 202; 'status_203'= Status code 203; 'status_204'= Status code 204; 'status_205'= Status code 205; 'status_206'= Status code 206; 'status_207'= Status code 207; 'status_100'= Status code 100; 'status_101'= Status code 101; 'status_102'= Status code 102; 'status_103'= Status code 103; 'status_300'= Status code 300; 'status_301'= Status code 301; 'status_302'= Status code 302; 'status_303'= Status code 303; 'status_304'= Status code 304; 'status_305'= Status code 305; 'status_306'= Status code 306; 'status_307'= Status code 307; 'status_400'= Status code 400; 'status_401'= Status code 401; 'status_402'= Status code 402; 'status_403'= Status code 403; 'status_404'= Status code 404; 'status_405'= Status code 405; 'status_406'= Status code 406; 'status_407'= Status code 407; 'status_408'= Status code 408; 'status_409'= Status code 409; 'status_410'= Status code 410; 'status_411'= Status code 411; 'status_412'= Status code 412; 'status_413'= Status code 413; 'status_414'= Status code 414; 'status_415'= Status code 415; 'status_416'= Status code 416; 'status_417'= Status code 417; 'status_418'= Status code 418; 'status_422'= Status code 422; 'status_423'= Status code 423; 'status_424'= Status code 424; 'status_425'= Status code 425; 'status_426'= Status code 426; 'status_449'= Status code 449; 'status_450'= Status code 450; 'status_500'= Status code 500; 'status_501'= Status code 501; 'status_502'= Status code 502; 'status_503'= Status code 503; 'status_504'= Status code 504; 'status_504_ax'= Status code 504 AX-gen; 'status_505'= Status code 505; 'status_506'= Status code 506; 'status_507'= Status code 507; 'status_508'= Status code 508; 'status_509'= Status code 509; 'status_510'= Status code 510; 'status_1xx'= status code 1XX; 'status_2xx'= status code 2XX; 'status_3xx'= status code 3XX; 'status_4xx'= status code 4XX; 'status_5xx'= status code 5XX; 'status_6xx'= status code 6XX; 'status_unknown'= Status code unknown; 'ws_handshake_request'= WS Handshake Req; 'ws_handshake_success'= WS Handshake Res; 'ws_client_switch'= WS Client Pkts; 'ws_server_switch'= WS Server Pkts; 'REQ_10u'= Rsp time less than 10u; 'REQ_20u'= Rsp time less than 20u; 'REQ_50u'= Rsp time less than 50u; 'REQ_100u'= Rsp time less than 100u; 'REQ_200u'= Rsp time less than 200u; 'REQ_500u'= Rsp time less than 500u; 'REQ_1m'= Rsp time less than 1m; 'REQ_2m'= Rsp time less than 2m; 'REQ_5m'= Rsp time less than 5m; 'REQ_10m'= Rsp time less than 10m; 'REQ_20m'= Rsp time less than 20m; 'REQ_50m'= Rsp time less than 5m; 'REQ_100m'= Rsp time less than 100m; 'REQ_200m'= Rsp time less than 200m; 'REQ_500m'= Rsp time less than 500m; 'REQ_1s'= Rsp time less than 1s; 'REQ_2s'= Rsp time less than 2s; 'REQ_5s'= Rsp time less than 5s; 'REQ_OVER_5s'= Rsp time greater than equal to 5s; 'total-requests'= Total number of Requests; 'header_length_long'= HTTP Header length too long; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            REQ_50u:
                description:
                - "Rsp time less than 50u"
            ws_server_switch:
                description:
                - "WS Server Pkts"
            REQ_50m:
                description:
                - "Rsp time less than 5m"
            status_450:
                description:
                - "Status code 450"
            status_510:
                description:
                - "Status code 510"
            ws_handshake_request:
                description:
                - "WS Handshake Req"
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
            ws_client_switch:
                description:
                - "WS Client Pkts"
            status_2xx:
                description:
                - "status code 2XX"
            REQ_500u:
                description:
                - "Rsp time less than 500u"
            status_4xx:
                description:
                - "status code 4XX"
            status_3xx:
                description:
                - "status code 3XX"
            REQ_200u:
                description:
                - "Rsp time less than 200u"
            REQ_100m:
                description:
                - "Rsp time less than 100m"
            REQ_5m:
                description:
                - "Rsp time less than 5m"
            REQ_100u:
                description:
                - "Rsp time less than 100u"
            REQ_5s:
                description:
                - "Rsp time less than 5s"
            REQ_500m:
                description:
                - "Rsp time less than 500m"
            header_length_long:
                description:
                - "HTTP Header length too long"
            REQ_20u:
                description:
                - "Rsp time less than 20u"
            REQ_2s:
                description:
                - "Rsp time less than 2s"
            status_306:
                description:
                - "Status code 306"
            status_307:
                description:
                - "Status code 307"
            status_304:
                description:
                - "Status code 304"
            status_305:
                description:
                - "Status code 305"
            status_302:
                description:
                - "Status code 302"
            status_303:
                description:
                - "Status code 303"
            REQ_2m:
                description:
                - "Rsp time less than 2m"
            status_301:
                description:
                - "Status code 301"
            REQ_10u:
                description:
                - "Rsp time less than 10u"
            REQ_10m:
                description:
                - "Rsp time less than 10m"
            REQ_200m:
                description:
                - "Rsp time less than 200m"
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
            status_103:
                description:
                - "Status code 103"
            status_300:
                description:
                - "Status code 300"
            status_424:
                description:
                - "Status code 424"
            ws_handshake_success:
                description:
                - "WS Handshake Res"
            status_504_ax:
                description:
                - "Status code 504 AX-gen"
            status_6xx:
                description:
                - "status code 6XX"
            status_5xx:
                description:
                - "status code 5XX"
            status_401:
                description:
                - "Status code 401"
            status_400:
                description:
                - "Status code 400"
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
            status_406:
                description:
                - "Status code 406"
            status_409:
                description:
                - "Status code 409"
            status_408:
                description:
                - "Status code 408"
            REQ_1m:
                description:
                - "Rsp time less than 1m"
            REQ_1s:
                description:
                - "Rsp time less than 1s"
            status_1xx:
                description:
                - "status code 1XX"
            total_requests:
                description:
                - "Total number of Requests"
            status_423:
                description:
                - "Status code 423"
            status_422:
                description:
                - "Status code 422"
            status_426:
                description:
                - "Status code 426"
            status_425:
                description:
                - "Status code 425"
            REQ_20m:
                description:
                - "Rsp time less than 20m"
            status_508:
                description:
                - "Status code 508"
            status_509:
                description:
                - "Status code 509"
            REQ_OVER_5s:
                description:
                - "Rsp time greater than equal to 5s"
            status_500:
                description:
                - "Status code 500"
            status_501:
                description:
                - "Status code 501"
            status_502:
                description:
                - "Status code 502"
            status_503:
                description:
                - "Status code 503"
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
            status_449:
                description:
                - "Status code 449"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","stats",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','status_200','status_201','status_202','status_203','status_204','status_205','status_206','status_207','status_100','status_101','status_102','status_103','status_300','status_301','status_302','status_303','status_304','status_305','status_306','status_307','status_400','status_401','status_402','status_403','status_404','status_405','status_406','status_407','status_408','status_409','status_410','status_411','status_412','status_413','status_414','status_415','status_416','status_417','status_418','status_422','status_423','status_424','status_425','status_426','status_449','status_450','status_500','status_501','status_502','status_503','status_504','status_504_ax','status_505','status_506','status_507','status_508','status_509','status_510','status_1xx','status_2xx','status_3xx','status_4xx','status_5xx','status_6xx','status_unknown','ws_handshake_request','ws_handshake_success','ws_client_switch','ws_server_switch','REQ_10u','REQ_20u','REQ_50u','REQ_100u','REQ_200u','REQ_500u','REQ_1m','REQ_2m','REQ_5m','REQ_10m','REQ_20m','REQ_50m','REQ_100m','REQ_200m','REQ_500m','REQ_1s','REQ_2s','REQ_5s','REQ_OVER_5s','total-requests','header_length_long'])),
        stats=dict(type='dict',REQ_50u=dict(type='str',),ws_server_switch=dict(type='str',),REQ_50m=dict(type='str',),status_450=dict(type='str',),status_510=dict(type='str',),ws_handshake_request=dict(type='str',),status_207=dict(type='str',),status_206=dict(type='str',),status_205=dict(type='str',),status_204=dict(type='str',),status_203=dict(type='str',),status_202=dict(type='str',),status_201=dict(type='str',),status_200=dict(type='str',),ws_client_switch=dict(type='str',),status_2xx=dict(type='str',),REQ_500u=dict(type='str',),status_4xx=dict(type='str',),status_3xx=dict(type='str',),REQ_200u=dict(type='str',),REQ_100m=dict(type='str',),REQ_5m=dict(type='str',),REQ_100u=dict(type='str',),REQ_5s=dict(type='str',),REQ_500m=dict(type='str',),header_length_long=dict(type='str',),REQ_20u=dict(type='str',),REQ_2s=dict(type='str',),status_306=dict(type='str',),status_307=dict(type='str',),status_304=dict(type='str',),status_305=dict(type='str',),status_302=dict(type='str',),status_303=dict(type='str',),REQ_2m=dict(type='str',),status_301=dict(type='str',),REQ_10u=dict(type='str',),REQ_10m=dict(type='str',),REQ_200m=dict(type='str',),status_412=dict(type='str',),status_413=dict(type='str',),status_410=dict(type='str',),status_411=dict(type='str',),status_416=dict(type='str',),status_417=dict(type='str',),status_414=dict(type='str',),status_415=dict(type='str',),status_418=dict(type='str',),status_unknown=dict(type='str',),status_100=dict(type='str',),status_101=dict(type='str',),status_102=dict(type='str',),status_103=dict(type='str',),status_300=dict(type='str',),status_424=dict(type='str',),ws_handshake_success=dict(type='str',),status_504_ax=dict(type='str',),status_6xx=dict(type='str',),status_5xx=dict(type='str',),status_401=dict(type='str',),status_400=dict(type='str',),status_403=dict(type='str',),status_402=dict(type='str',),status_405=dict(type='str',),status_404=dict(type='str',),status_407=dict(type='str',),status_406=dict(type='str',),status_409=dict(type='str',),status_408=dict(type='str',),REQ_1m=dict(type='str',),REQ_1s=dict(type='str',),status_1xx=dict(type='str',),total_requests=dict(type='str',),status_423=dict(type='str',),status_422=dict(type='str',),status_426=dict(type='str',),status_425=dict(type='str',),REQ_20m=dict(type='str',),status_508=dict(type='str',),status_509=dict(type='str',),REQ_OVER_5s=dict(type='str',),status_500=dict(type='str',),status_501=dict(type='str',),status_502=dict(type='str',),status_503=dict(type='str',),status_504=dict(type='str',),status_505=dict(type='str',),status_506=dict(type='str',),status_507=dict(type='str',),status_449=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/counter/http_vport/{sampling-enable}"

    f_dict = {}
    f_dict["sampling-enable"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/counter/http_vport/{sampling-enable}"

    f_dict = {}
    f_dict["sampling-enable"] = module.params["sampling_enable"]

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["http_vport"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["http_vport"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["http_vport"][k] = v
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
    payload = build_json("http_vport", module)
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
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
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