#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
    partition:
        description:
        - Destination/target partition for object/command
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'download_bad_blocked'= Download malware blocked; 'download_bad_allowed'= Download malware allowed; 'download_bad_ext_inspect'= Download malware extrnal inspect; 'download_suspect_blocked'= Download suspect blocked; 'download_suspect_ext_inspect'= Download suspect extrnal inspect; 'download_suspect_allowed'= Download suspect allowed; 'download_good_blocked'= Download safe blocked; 'download_good_allowed'= Download safe external inspect; 'download_good_ext_inspect'= Download safe allowed; 'upload_bad_blocked'= Upload malware blocked; 'upload_bad_allowed'= Upload malware allowed; 'upload_bad_ext_inspect'= Upload malware extrnal inspect; 'upload_suspect_blocked'= Upload suspect blocked; 'upload_suspect_ext_inspect'= Upload suspect extrnal inspect; 'upload_suspect_allowed'= Upload suspect allowed; 'upload_good_blocked'= Upload safe blocked; 'upload_good_ext_inspect'= Upload safe external inspect; 'upload_good_allowed'= Upload safe allowed; 'icap_200'= Receive icap status 200; 'icap_204'= Receive icap status 204; 'icap_500'= Receive icap status 500; 'icap_other_status_code'= Receive icap other status code; 'icap_connect_fail'= Icap connect fail; 'icap_connection_created'= Icap connection created; 'icap_connection_established'= Icap connection established; 'icap_connection_closed'= Icap connection closed; 'icap_connection_rst'= Icap connection rst; 'icap_bytes_sent'= Icap bytes sent; 'icap_bytes_received'= Icap bytes received; 'bypass_aflex'= Bypassed by aflex; 'bypass_large_file'= Bypassed - large file size; 'bypass_service_disabled'= Bypassed - Internal service disabled; 'bypass_service_down'= Bypassed - Internal service down; 'reset_service_down'= Reset - Internal service down; 'bypass_max_concurrent_files_reached'= Bypassed - max concurrent files on server reached; 'bypass_non_inspection'= Bypassed non inspection data; 'non_supported_file'= Non supported file type; 'transactions_alloc'= Total transactions allocated; 'transactions_free'= Total transactions freed; 'transactions_failure'= Total transactions failure; 'transactions_aborted'= Total transactions aborted; 'orig_conn_bytes_received'= Original connection bytes received; 'orig_conn_bytes_sent'= Original connection bytes sent; 'orig_conn_bytes_bypassed'= Original connection bytes bypassed; 'bypass_buffered_overlimit'= Total Bytes Buffered Overlimit; 'total_bandwidth'= Total File Bytes; 'total_suspect_bandwidth'= Total Suspected Files Bytes; 'total_bad_bandwidth'= Total Bad Files Bytes; 'total_good_bandwidth'= Total Good Files Bytes; 'total_file_size_less_1m'= Total Files Less than 1Mb; 'total_file_size_1_5m'= Total Files Between 1-5Mb; 'total_file_size_5_8m'= Total Files Between 5-8Mb; 'total_file_size_8_32m'= Total Files Between 8-32Mb; 'total_file_size_over_32m'= Total Files over 32Mb; 'suspect_file_size_less_1m'= Suspect Files Less than 1Mb; 'suspect_file_size_1_5m'= Suspect Files Between 1-5Mb; 'suspect_file_size_5_8m'= Suspect Files Between 5-8Mb; 'suspect_file_size_8_32m'= Suspect Files Between 8-32Mb; 'suspect_file_size_over_32m'= Suspect Files over 32Mb; 'good_file_size_less_1m'= Good Files Less than 1Mb; 'good_file_size_1_5m'= Good Files Between 1-5Mb; 'good_file_size_5_8m'= Good Files Between 5-8Mb; 'good_file_size_8_32m'= Good Files Between 8-32Mb; 'good_file_size_over_32m'= Good Files over 32Mb; 'bad_file_size_less_1m'= Bad Files Less than 1Mb; 'bad_file_size_1_5m'= Bad Files Between 1-5Mb; 'bad_file_size_5_8m'= Bad Files Between 5-8Mb; 'bad_file_size_8_32m'= Bad Files Between 8-32Mb; 'bad_file_size_over_32m'= Bad Files over 32Mb; "
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','download_bad_blocked','download_bad_allowed','download_bad_ext_inspect','download_suspect_blocked','download_suspect_ext_inspect','download_suspect_allowed','download_good_blocked','download_good_allowed','download_good_ext_inspect','upload_bad_blocked','upload_bad_allowed','upload_bad_ext_inspect','upload_suspect_blocked','upload_suspect_ext_inspect','upload_suspect_allowed','upload_good_blocked','upload_good_ext_inspect','upload_good_allowed','icap_200','icap_204','icap_500','icap_other_status_code','icap_connect_fail','icap_connection_created','icap_connection_established','icap_connection_closed','icap_connection_rst','icap_bytes_sent','icap_bytes_received','bypass_aflex','bypass_large_file','bypass_service_disabled','bypass_service_down','reset_service_down','bypass_max_concurrent_files_reached','bypass_non_inspection','non_supported_file','transactions_alloc','transactions_free','transactions_failure','transactions_aborted','orig_conn_bytes_received','orig_conn_bytes_sent','orig_conn_bytes_bypassed','bypass_buffered_overlimit','total_bandwidth','total_suspect_bandwidth','total_bad_bandwidth','total_good_bandwidth','total_file_size_less_1m','total_file_size_1_5m','total_file_size_5_8m','total_file_size_8_32m','total_file_size_over_32m','suspect_file_size_less_1m','suspect_file_size_1_5m','suspect_file_size_5_8m','suspect_file_size_8_32m','suspect_file_size_over_32m','good_file_size_less_1m','good_file_size_1_5m','good_file_size_5_8m','good_file_size_8_32m','good_file_size_over_32m','bad_file_size_less_1m','bad_file_size_1_5m','bad_file_size_5_8m','bad_file_size_8_32m','bad_file_size_over_32m'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/file-inspection/global-stat"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/file-inspection/global-stat"

    f_dict = {}

    return url_base.format(**f_dict)

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
        if v:
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("global-stat", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
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

def update(module, result, existing_config):
    payload = build_json("global-stat", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("global-stat", module)
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
    
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()