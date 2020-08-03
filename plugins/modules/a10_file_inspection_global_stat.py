#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_file_inspection_global_stat
description:
    - global stats
short_description: Configures A10 file.inspection.global-stat
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
    file_content:
        description:
        - Content of the uploaded file
        note:
        - Use 'lookup' ansible command to provide required data
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'download_bad_blocked'= Download malware blocked; 'download_bad_allowed'= Download malware allowed; 'download_bad_ext_inspect'= Download malware extrnal inspect; 'download_suspect_blocked'= Download suspect blocked; 'download_suspect_ext_inspect'= Download suspect extrnal inspect; 'download_suspect_allowed'= Download suspect allowed; 'download_good_blocked'= Download safe blocked; 'download_good_allowed'= Download safe external inspect; 'download_good_ext_inspect'= Download safe allowed; 'upload_bad_blocked'= Upload malware blocked; 'upload_bad_allowed'= Upload malware allowed; 'upload_bad_ext_inspect'= Upload malware extrnal inspect; 'upload_suspect_blocked'= Upload suspect blocked; 'upload_suspect_ext_inspect'= Upload suspect extrnal inspect; 'upload_suspect_allowed'= Upload suspect allowed; 'upload_good_blocked'= Upload safe blocked; 'upload_good_ext_inspect'= Upload safe external inspect; 'upload_good_allowed'= Upload safe allowed; 'icap_200'= Receive icap status 200; 'icap_204'= Receive icap status 204; 'icap_500'= Receive icap status 500; 'icap_other_status_code'= Receive icap other status code; 'icap_connect_fail'= Icap connect fail; 'icap_connection_created'= Icap connection created; 'icap_connection_established'= Icap connection established; 'icap_connection_closed'= Icap connection closed; 'icap_connection_rst'= Icap connection rst; 'icap_bytes_sent'= Icap bytes sent; 'icap_bytes_received'= Icap bytes received; 'bypass_aflex'= Bypassed by aflex; 'bypass_large_file'= Bypassed - large file size; 'bypass_service_disabled'= Bypassed - Internal service disabled; 'bypass_service_down'= Bypassed - Internal service down; 'reset_service_down'= Reset - Internal service down; 'bypass_max_concurrent_files_reached'= Bypassed - max concurrent files on server reached; 'bypass_non_inspection'= Bypassed non inspection data; 'non_supported_file'= Non supported file type; 'transactions_alloc'= Total transactions allocated; 'transactions_free'= Total transactions freed; 'transactions_failure'= Total transactions failure; 'transactions_aborted'= Total transactions aborted; 'orig_conn_bytes_received'= Original connection bytes received; 'orig_conn_bytes_sent'= Original connection bytes sent; 'orig_conn_bytes_bypassed'= Original connection bytes bypassed; 'bypass_buffered_overlimit'= Total Bytes Buffered Overlimit; 'total_bandwidth'= Total File Bytes; 'total_suspect_bandwidth'= Total Suspected Files Bytes; 'total_bad_bandwidth'= Total Bad Files Bytes; 'total_good_bandwidth'= Total Good Files Bytes; 'total_file_size_less_1m'= Total Files Less than 1Mb; 'total_file_size_1_5m'= Total Files Between 1-5Mb; 'total_file_size_5_8m'= Total Files Between 5-8Mb; 'total_file_size_8_32m'= Total Files Between 8-32Mb; 'total_file_size_over_32m'= Total Files over 32Mb; 'suspect_file_size_less_1m'= Suspect Files Less than 1Mb; 'suspect_file_size_1_5m'= Suspect Files Between 1-5Mb; 'suspect_file_size_5_8m'= Suspect Files Between 5-8Mb; 'suspect_file_size_8_32m'= Suspect Files Between 8-32Mb; 'suspect_file_size_over_32m'= Suspect Files over 32Mb; 'good_file_size_less_1m'= Good Files Less than 1Mb; 'good_file_size_1_5m'= Good Files Between 1-5Mb; 'good_file_size_5_8m'= Good Files Between 5-8Mb; 'good_file_size_8_32m'= Good Files Between 8-32Mb; 'good_file_size_over_32m'= Good Files over 32Mb; 'bad_file_size_less_1m'= Bad Files Less than 1Mb; 'bad_file_size_1_5m'= Bad Files Between 1-5Mb; 'bad_file_size_5_8m'= Bad Files Between 5-8Mb; 'bad_file_size_8_32m'= Bad Files Between 8-32Mb; 'bad_file_size_over_32m'= Bad Files over 32Mb; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            icap_200:
                description:
                - "Receive icap status 200"
            bypass_service_down:
                description:
                - "Bypassed - Internal service down"
            upload_good_ext_inspect:
                description:
                - "Upload safe external inspect"
            upload_bad_blocked:
                description:
                - "Upload malware blocked"
            bad_file_size_less_1m:
                description:
                - "Bad Files Less than 1Mb"
            suspect_file_size_1_5m:
                description:
                - "Suspect Files Between 1-5Mb"
            orig_conn_bytes_bypassed:
                description:
                - "Original connection bytes bypassed"
            upload_suspect_allowed:
                description:
                - "Upload suspect allowed"
            suspect_file_size_5_8m:
                description:
                - "Suspect Files Between 5-8Mb"
            total_file_size_less_1m:
                description:
                - "Total Files Less than 1Mb"
            upload_bad_ext_inspect:
                description:
                - "Upload malware extrnal inspect"
            orig_conn_bytes_sent:
                description:
                - "Original connection bytes sent"
            total_file_size_1_5m:
                description:
                - "Total Files Between 1-5Mb"
            download_suspect_allowed:
                description:
                - "Download suspect allowed"
            non_supported_file:
                description:
                - "Non supported file type"
            icap_204:
                description:
                - "Receive icap status 204"
            suspect_file_size_8_32m:
                description:
                - "Suspect Files Between 8-32Mb"
            total_file_size_5_8m:
                description:
                - "Total Files Between 5-8Mb"
            icap_connect_fail:
                description:
                - "Icap connect fail"
            upload_good_blocked:
                description:
                - "Upload safe blocked"
            icap_other_status_code:
                description:
                - "Receive icap other status code"
            bypass_aflex:
                description:
                - "Bypassed by aflex"
            good_file_size_over_32m:
                description:
                - "Good Files over 32Mb"
            total_suspect_bandwidth:
                description:
                - "Total Suspected Files Bytes"
            orig_conn_bytes_received:
                description:
                - "Original connection bytes received"
            download_suspect_ext_inspect:
                description:
                - "Download suspect extrnal inspect"
            good_file_size_8_32m:
                description:
                - "Good Files Between 8-32Mb"
            reset_service_down:
                description:
                - "Reset - Internal service down"
            icap_500:
                description:
                - "Receive icap status 500"
            bad_file_size_5_8m:
                description:
                - "Bad Files Between 5-8Mb"
            upload_suspect_ext_inspect:
                description:
                - "Upload suspect extrnal inspect"
            bypass_large_file:
                description:
                - "Bypassed - large file size"
            icap_bytes_sent:
                description:
                - "Icap bytes sent"
            download_good_allowed:
                description:
                - "Download safe external inspect"
            download_bad_blocked:
                description:
                - "Download malware blocked"
            total_bad_bandwidth:
                description:
                - "Total Bad Files Bytes"
            bad_file_size_over_32m:
                description:
                - "Bad Files over 32Mb"
            download_bad_ext_inspect:
                description:
                - "Download malware extrnal inspect"
            transactions_aborted:
                description:
                - "Total transactions aborted"
            total_good_bandwidth:
                description:
                - "Total Good Files Bytes"
            bypass_non_inspection:
                description:
                - "Bypassed non inspection data"
            download_good_blocked:
                description:
                - "Download safe blocked"
            total_bandwidth:
                description:
                - "Total File Bytes"
            download_bad_allowed:
                description:
                - "Download malware allowed"
            bypass_buffered_overlimit:
                description:
                - "Total Bytes Buffered Overlimit"
            download_good_ext_inspect:
                description:
                - "Download safe allowed"
            download_suspect_blocked:
                description:
                - "Download suspect blocked"
            upload_suspect_blocked:
                description:
                - "Upload suspect blocked"
            good_file_size_less_1m:
                description:
                - "Good Files Less than 1Mb"
            bad_file_size_8_32m:
                description:
                - "Bad Files Between 8-32Mb"
            icap_connection_rst:
                description:
                - "Icap connection rst"
            total_file_size_over_32m:
                description:
                - "Total Files over 32Mb"
            good_file_size_1_5m:
                description:
                - "Good Files Between 1-5Mb"
            suspect_file_size_less_1m:
                description:
                - "Suspect Files Less than 1Mb"
            icap_bytes_received:
                description:
                - "Icap bytes received"
            icap_connection_established:
                description:
                - "Icap connection established"
            icap_connection_closed:
                description:
                - "Icap connection closed"
            good_file_size_5_8m:
                description:
                - "Good Files Between 5-8Mb"
            transactions_alloc:
                description:
                - "Total transactions allocated"
            upload_bad_allowed:
                description:
                - "Upload malware allowed"
            icap_connection_created:
                description:
                - "Icap connection created"
            bypass_max_concurrent_files_reached:
                description:
                - "Bypassed - max concurrent files on server reached"
            total_file_size_8_32m:
                description:
                - "Total Files Between 8-32Mb"
            transactions_free:
                description:
                - "Total transactions freed"
            bypass_service_disabled:
                description:
                - "Bypassed - Internal service disabled"
            upload_good_allowed:
                description:
                - "Upload safe allowed"
            transactions_failure:
                description:
                - "Total transactions failure"
            suspect_file_size_over_32m:
                description:
                - "Suspect Files over 32Mb"
            bad_file_size_1_5m:
                description:
                - "Bad Files Between 1-5Mb"
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
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        file_content = dict(type='str', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'download_bad_blocked', 'download_bad_allowed', 'download_bad_ext_inspect', 'download_suspect_blocked', 'download_suspect_ext_inspect', 'download_suspect_allowed', 'download_good_blocked', 'download_good_allowed', 'download_good_ext_inspect', 'upload_bad_blocked', 'upload_bad_allowed', 'upload_bad_ext_inspect', 'upload_suspect_blocked', 'upload_suspect_ext_inspect', 'upload_suspect_allowed', 'upload_good_blocked', 'upload_good_ext_inspect', 'upload_good_allowed', 'icap_200', 'icap_204', 'icap_500', 'icap_other_status_code', 'icap_connect_fail', 'icap_connection_created', 'icap_connection_established', 'icap_connection_closed', 'icap_connection_rst', 'icap_bytes_sent', 'icap_bytes_received', 'bypass_aflex', 'bypass_large_file', 'bypass_service_disabled', 'bypass_service_down', 'reset_service_down', 'bypass_max_concurrent_files_reached', 'bypass_non_inspection', 'non_supported_file', 'transactions_alloc', 'transactions_free', 'transactions_failure', 'transactions_aborted', 'orig_conn_bytes_received', 'orig_conn_bytes_sent', 'orig_conn_bytes_bypassed', 'bypass_buffered_overlimit', 'total_bandwidth', 'total_suspect_bandwidth', 'total_bad_bandwidth', 'total_good_bandwidth', 'total_file_size_less_1m', 'total_file_size_1_5m', 'total_file_size_5_8m', 'total_file_size_8_32m', 'total_file_size_over_32m', 'suspect_file_size_less_1m', 'suspect_file_size_1_5m', 'suspect_file_size_5_8m', 'suspect_file_size_8_32m', 'suspect_file_size_over_32m', 'good_file_size_less_1m', 'good_file_size_1_5m', 'good_file_size_5_8m', 'good_file_size_8_32m', 'good_file_size_over_32m', 'bad_file_size_less_1m', 'bad_file_size_1_5m', 'bad_file_size_5_8m', 'bad_file_size_8_32m', 'bad_file_size_over_32m'])),
        stats=dict(type='dict', icap_200=dict(type='str', ), bypass_service_down=dict(type='str', ), upload_good_ext_inspect=dict(type='str', ), upload_bad_blocked=dict(type='str', ), bad_file_size_less_1m=dict(type='str', ), suspect_file_size_1_5m=dict(type='str', ), orig_conn_bytes_bypassed=dict(type='str', ), upload_suspect_allowed=dict(type='str', ), suspect_file_size_5_8m=dict(type='str', ), total_file_size_less_1m=dict(type='str', ), upload_bad_ext_inspect=dict(type='str', ), orig_conn_bytes_sent=dict(type='str', ), total_file_size_1_5m=dict(type='str', ), download_suspect_allowed=dict(type='str', ), non_supported_file=dict(type='str', ), icap_204=dict(type='str', ), suspect_file_size_8_32m=dict(type='str', ), total_file_size_5_8m=dict(type='str', ), icap_connect_fail=dict(type='str', ), upload_good_blocked=dict(type='str', ), icap_other_status_code=dict(type='str', ), bypass_aflex=dict(type='str', ), good_file_size_over_32m=dict(type='str', ), total_suspect_bandwidth=dict(type='str', ), orig_conn_bytes_received=dict(type='str', ), download_suspect_ext_inspect=dict(type='str', ), good_file_size_8_32m=dict(type='str', ), reset_service_down=dict(type='str', ), icap_500=dict(type='str', ), bad_file_size_5_8m=dict(type='str', ), upload_suspect_ext_inspect=dict(type='str', ), bypass_large_file=dict(type='str', ), icap_bytes_sent=dict(type='str', ), download_good_allowed=dict(type='str', ), download_bad_blocked=dict(type='str', ), total_bad_bandwidth=dict(type='str', ), bad_file_size_over_32m=dict(type='str', ), download_bad_ext_inspect=dict(type='str', ), transactions_aborted=dict(type='str', ), total_good_bandwidth=dict(type='str', ), bypass_non_inspection=dict(type='str', ), download_good_blocked=dict(type='str', ), total_bandwidth=dict(type='str', ), download_bad_allowed=dict(type='str', ), bypass_buffered_overlimit=dict(type='str', ), download_good_ext_inspect=dict(type='str', ), download_suspect_blocked=dict(type='str', ), upload_suspect_blocked=dict(type='str', ), good_file_size_less_1m=dict(type='str', ), bad_file_size_8_32m=dict(type='str', ), icap_connection_rst=dict(type='str', ), total_file_size_over_32m=dict(type='str', ), good_file_size_1_5m=dict(type='str', ), suspect_file_size_less_1m=dict(type='str', ), icap_bytes_received=dict(type='str', ), icap_connection_established=dict(type='str', ), icap_connection_closed=dict(type='str', ), good_file_size_5_8m=dict(type='str', ), transactions_alloc=dict(type='str', ), upload_bad_allowed=dict(type='str', ), icap_connection_created=dict(type='str', ), bypass_max_concurrent_files_reached=dict(type='str', ), total_file_size_8_32m=dict(type='str', ), transactions_free=dict(type='str', ), bypass_service_disabled=dict(type='str', ), upload_good_allowed=dict(type='str', ), transactions_failure=dict(type='str', ), suspect_file_size_over_32m=dict(type='str', ), bad_file_size_1_5m=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/file-inspection/global-stat"

    f_dict = {}

    return url_base.format(**f_dict)

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/file-inspection/global-stat"

    f_dict = {}

    return url_base.format(**f_dict)

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
        for k, v in payload["global-stat"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["global-stat"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["global-stat"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        if module.params["action"] == "import":
            post_result = module.client.post(new_url(module), payload, file_content=module.params["file_content"], file_name=module.params["file"])
        else:
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
    payload = build_json("global-stat", module)
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

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