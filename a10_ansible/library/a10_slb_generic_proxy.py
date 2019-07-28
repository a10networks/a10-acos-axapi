#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_generic_proxy
description:
    - Show Generic Proxy Statistics
short_description: Configures A10 slb.generic-proxy
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
                - "'all'= all; 'num'= Number; 'curr'= Current; 'total'= Total; 'svrsel_fail'= Number of server selection failed; 'no_route'= Number of no routes; 'snat_fail'= Number of snat failures; 'client_fail'= Number of client failures; 'server_fail'= Number of server failures; 'no_sess'= Number of no sessions; 'user_session'= Number of user sessions; 'acr_out'= Number of ACRs out; 'acr_in'= Number of ACRs in; 'aca_out'= Number of ACAs out; 'aca_in'= Number of ACAs in; 'cea_out'= Number of CEAs out; 'cea_in'= Number of CEAs in; 'cer_out'= Number of CERs out; 'cer_in'= Number of CERs in; 'dwr_out'= Number of DWRs out; 'dwr_in'= Number of DWRs in; 'dwa_out'= Number of DWAs out; 'dwa_in'= Number of DWAs in; 'str_out'= Number of STRs out; 'str_in'= Number of STRs in; 'sta_out'= Number of STAs out; 'sta_in'= Number of STAs in; 'asr_out'= Number of ASRs out; 'asr_in'= Number of ASRs in; 'asa_out'= Number of ASAs out; 'asa_in'= Number of ASAs in; 'other_out'= Number of other messages out; 'other_in'= Number of other messages in; 'total_http_req_enter_gen'= Total number of HTTP requests enter generic proxy; 'mismatch_fwd_id'= Diameter mismatch fwd session id; 'mismatch_rev_id'= Diameter mismatch rev session id; 'unkwn_cmd_code'= Diameter unkown cmd code; 'no_session_id'= Diameter no session id avp; 'no_fwd_tuple'= Diameter no fwd tuple matched; 'no_rev_tuple'= Diameter no rev tuple matched; 'dcmsg_fwd_in'= Diameter cross cpu fwd in; 'dcmsg_fwd_out'= Diameter cross cpu fwd out; 'dcmsg_rev_in'= Diameter cross cpu rev in; 'dcmsg_rev_out'= Diameter cross cpu rev out; 'dcmsg_error'= Diameter cross cpu error; 'retry_client_request'= Diameter retry client request; 'retry_client_request_fail'= Diameter retry client request fail; 'reply_unknown_session_id'= Reply with unknown session ID error info; 'ccr_out'= Number of CCRs out; 'ccr_in'= Number of CCRs in; 'cca_out'= Number of CCAs out; 'cca_in'= Number of CCAs in; 'ccr_i'= Number of CCRs initial; 'ccr_u'= Number of CCRs update; 'ccr_t'= Number of CCRs terminate; 'cca_t'= Number of CCAs terminate; 'terminate_on_cca_t'= Diameter terminate on cca_t; 'forward_unknown_session_id'= Forward server side message with unknown session id; 'update_latest_server'= Update to the latest server that used a session id; 'client_select_fail'= Fail to select client; 'close_conn_when_vport_down'= Close client conn when virtual port is down; 'invalid_avp'= AVP value contains illegal chars; 'reselect_fwd_tuple'= Original client tuple does not exist so reselect another one; 'reselect_fwd_tuple_other_cpu'= Original client tuple does not exist so reselect another one on other CPUs; 'reselect_rev_tuple'= Original server tuple does not exist so reselect another one; 'conn_closed_by_client'= Client initiates TCP close/reset; 'conn_closed_by_server'= Server initiates TCP close/reset; 'reply_invalid_avp_value'= Reply with invalid AVP error info; 'reply_unable_to_deliver'= Reply with unable to deliver error info; 'reply_error_info_fail'= Fail to reply error info to peer; 'dpr_out'= Number of DPRs out; 'dpr_in'= Number of DPRs in; 'dpa_out'= Number of DPAs out; 'dpa_in'= Number of DPAs in; "
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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','curr','total','svrsel_fail','no_route','snat_fail','client_fail','server_fail','no_sess','user_session','acr_out','acr_in','aca_out','aca_in','cea_out','cea_in','cer_out','cer_in','dwr_out','dwr_in','dwa_out','dwa_in','str_out','str_in','sta_out','sta_in','asr_out','asr_in','asa_out','asa_in','other_out','other_in','total_http_req_enter_gen','mismatch_fwd_id','mismatch_rev_id','unkwn_cmd_code','no_session_id','no_fwd_tuple','no_rev_tuple','dcmsg_fwd_in','dcmsg_fwd_out','dcmsg_rev_in','dcmsg_rev_out','dcmsg_error','retry_client_request','retry_client_request_fail','reply_unknown_session_id','ccr_out','ccr_in','cca_out','cca_in','ccr_i','ccr_u','ccr_t','cca_t','terminate_on_cca_t','forward_unknown_session_id','update_latest_server','client_select_fail','close_conn_when_vport_down','invalid_avp','reselect_fwd_tuple','reselect_fwd_tuple_other_cpu','reselect_rev_tuple','conn_closed_by_client','conn_closed_by_server','reply_invalid_avp_value','reply_unable_to_deliver','reply_error_info_fail','dpr_out','dpr_in','dpa_out','dpa_in'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/generic-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/generic-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("generic-proxy", module)
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
    payload = build_json("generic-proxy", module)
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
    payload = build_json("generic-proxy", module)
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
        message=""
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
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