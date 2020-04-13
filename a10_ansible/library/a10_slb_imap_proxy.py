#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_imap_proxy
description:
    - Configure IMAP Proxy global
short_description: Configures A10 slb.imap-proxy
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
    device_id:
        description:
        - Device ID for configuration
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
                - "'all'= all; 'num'= Num; 'curr'= Current proxy conns; 'total'= Total proxy conns; 'svrsel_fail'= Server selection failure; 'no_route'= no route failure; 'snat_fail'= source nat failure; 'feat'= feat packet; 'cc'= clear ctrl port packet; 'data_ssl'= data ssl force; 'line_too_long'= line too long; 'line_mem_freed'= request line freed; 'invalid_start_line'= invalid start line; 'auth_tls'= auth tls cmd; 'prot'= prot cmd; 'pbsz'= pbsz cmd; 'pasv'= pasv cmd; 'port'= port cmd; 'request_dont_care'= other cmd; 'client_auth_tls'= client auth tls; 'cant_find_pasv'= cant find pasv; 'pasv_addr_ne_server'= psv addr not equal to svr; 'smp_create_fail'= smp create fail; 'data_server_conn_fail'= data svr conn fail; 'data_send_fail'= data send fail; 'epsv'= epsv command; 'cant_find_epsv'= cant find epsv; 'data_curr'= Current Data Proxy; 'data_total'= Total Data Proxy; 'auth_unsupported'= Unsupported auth; 'adat'= adat cmd; 'unsupported_pbsz_value'= Unsupported PBSZ; 'unsupported_prot_value'= Unsupported PROT; 'unsupported_command'= Unsupported cmd; 'control_to_clear'= Control chn clear txt; 'control_to_ssl'= Control chn ssl; 'bad_sequence'= Bad Sequence; 'rsv_persist_conn_fail'= Serv Sel Persist fail; 'smp_v6_fail'= Serv Sel SMPv6 fail; 'smp_v4_fail'= Serv Sel SMPv4 fail; 'insert_tuple_fail'= Serv Sel insert tuple fail; 'cl_est_err'= Client EST state erro; 'ser_connecting_err'= Serv CTNG state error; 'server_response_err'= Serv RESP state error; 'cl_request_err'= Client RQ state error; 'data_conn_start_err'= Data Start state error; 'data_serv_connecting_err'= Data Serv CTNG error; 'data_serv_connected_err'= Data Serv CTED error; 'request'= Total FTP Request; 'capability'= Capability cmd; 'start_tls'= Total Start TLS cmd; 'login'= Total Login cmd; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            ser_connecting_err:
                description:
                - "Serv CTNG state error"
            svrsel_fail:
                description:
                - "Server selection failure"
            curr:
                description:
                - "Current proxy conns"
            client_auth_tls:
                description:
                - "client auth tls"
            cc:
                description:
                - "clear ctrl port packet"
            adat:
                description:
                - "adat cmd"
            server_response_err:
                description:
                - "Serv RESP state error"
            unsupported_pbsz_value:
                description:
                - "Unsupported PBSZ"
            cant_find_pasv:
                description:
                - "cant find pasv"
            pbsz:
                description:
                - "pbsz cmd"
            pasv:
                description:
                - "pasv cmd"
            num:
                description:
                - "Num"
            no_route:
                description:
                - "no route failure"
            smp_v4_fail:
                description:
                - "Serv Sel SMPv4 fail"
            total:
                description:
                - "Total proxy conns"
            feat:
                description:
                - "feat packet"
            port:
                description:
                - "port cmd"
            cant_find_epsv:
                description:
                - "cant find epsv"
            auth_tls:
                description:
                - "auth tls cmd"
            unsupported_command:
                description:
                - "Unsupported cmd"
            request_dont_care:
                description:
                - "other cmd"
            cl_est_err:
                description:
                - "Client EST state erro"
            prot:
                description:
                - "prot cmd"
            insert_tuple_fail:
                description:
                - "Serv Sel insert tuple fail"
            line_mem_freed:
                description:
                - "request line freed"
            start_tls:
                description:
                - "Total Start TLS cmd"
            data_conn_start_err:
                description:
                - "Data Start state error"
            invalid_start_line:
                description:
                - "invalid start line"
            epsv:
                description:
                - "epsv command"
            rsv_persist_conn_fail:
                description:
                - "Serv Sel Persist fail"
            cl_request_err:
                description:
                - "Client RQ state error"
            data_total:
                description:
                - "Total Data Proxy"
            smp_v6_fail:
                description:
                - "Serv Sel SMPv6 fail"
            data_curr:
                description:
                - "Current Data Proxy"
            snat_fail:
                description:
                - "source nat failure"
            data_ssl:
                description:
                - "data ssl force"
            data_serv_connecting_err:
                description:
                - "Data Serv CTNG error"
            auth_unsupported:
                description:
                - "Unsupported auth"
            smp_create_fail:
                description:
                - "smp create fail"
            control_to_clear:
                description:
                - "Control chn clear txt"
            pasv_addr_ne_server:
                description:
                - "psv addr not equal to svr"
            data_serv_connected_err:
                description:
                - "Data Serv CTED error"
            unsupported_prot_value:
                description:
                - "Unsupported PROT"
            request:
                description:
                - "Total FTP Request"
            bad_sequence:
                description:
                - "Bad Sequence"
            capability:
                description:
                - "Capability cmd"
            data_send_fail:
                description:
                - "data send fail"
            control_to_ssl:
                description:
                - "Control chn ssl"
            line_too_long:
                description:
                - "line too long"
            login:
                description:
                - "Total Login cmd"
            data_server_conn_fail:
                description:
                - "data svr conn fail"
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
AVAILABLE_PROPERTIES = ["oper","sampling_enable","stats","uuid",]

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
        device_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',l4_cpu_list=dict(type='list',serv_sel_smpv4_fail=dict(type='int',),client_est_state_err=dict(type='int',),inv_start_line=dict(type='int',),server_selection_failure=dict(type='int',),imap_line_too_long=dict(type='int',),login_packet=dict(type='int',),serv_sel_smpv6_fail=dict(type='int',),other_cmd=dict(type='int',),capability_packet=dict(type='int',),serv_sel_ins_tpl_fail=dict(type='int',),total_imap_request=dict(type='int',),serv_sel_persist_fail=dict(type='int',),source_nat_failure=dict(type='int',),serv_resp_state_err=dict(type='int',),total_proxy_conns=dict(type='int',),no_route_failure=dict(type='int',),client_rq_state_err=dict(type='int',),control_chn_ssl=dict(type='int',),bad_seq=dict(type='int',),current_proxy_conns=dict(type='int',),request_line_freed=dict(type='int',),serv_ctng_state_err=dict(type='int',),start_tls_cmd=dict(type='int',)),cpu_count=dict(type='int',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','curr','total','svrsel_fail','no_route','snat_fail','feat','cc','data_ssl','line_too_long','line_mem_freed','invalid_start_line','auth_tls','prot','pbsz','pasv','port','request_dont_care','client_auth_tls','cant_find_pasv','pasv_addr_ne_server','smp_create_fail','data_server_conn_fail','data_send_fail','epsv','cant_find_epsv','data_curr','data_total','auth_unsupported','adat','unsupported_pbsz_value','unsupported_prot_value','unsupported_command','control_to_clear','control_to_ssl','bad_sequence','rsv_persist_conn_fail','smp_v6_fail','smp_v4_fail','insert_tuple_fail','cl_est_err','ser_connecting_err','server_response_err','cl_request_err','data_conn_start_err','data_serv_connecting_err','data_serv_connected_err','request','capability','start_tls','login'])),
        stats=dict(type='dict',ser_connecting_err=dict(type='str',),svrsel_fail=dict(type='str',),curr=dict(type='str',),client_auth_tls=dict(type='str',),cc=dict(type='str',),adat=dict(type='str',),server_response_err=dict(type='str',),unsupported_pbsz_value=dict(type='str',),cant_find_pasv=dict(type='str',),pbsz=dict(type='str',),pasv=dict(type='str',),num=dict(type='str',),no_route=dict(type='str',),smp_v4_fail=dict(type='str',),total=dict(type='str',),feat=dict(type='str',),port=dict(type='str',),cant_find_epsv=dict(type='str',),auth_tls=dict(type='str',),unsupported_command=dict(type='str',),request_dont_care=dict(type='str',),cl_est_err=dict(type='str',),prot=dict(type='str',),insert_tuple_fail=dict(type='str',),line_mem_freed=dict(type='str',),start_tls=dict(type='str',),data_conn_start_err=dict(type='str',),invalid_start_line=dict(type='str',),epsv=dict(type='str',),rsv_persist_conn_fail=dict(type='str',),cl_request_err=dict(type='str',),data_total=dict(type='str',),smp_v6_fail=dict(type='str',),data_curr=dict(type='str',),snat_fail=dict(type='str',),data_ssl=dict(type='str',),data_serv_connecting_err=dict(type='str',),auth_unsupported=dict(type='str',),smp_create_fail=dict(type='str',),control_to_clear=dict(type='str',),pasv_addr_ne_server=dict(type='str',),data_serv_connected_err=dict(type='str',),unsupported_prot_value=dict(type='str',),request=dict(type='str',),bad_sequence=dict(type='str',),capability=dict(type='str',),data_send_fail=dict(type='str',),control_to_ssl=dict(type='str',),line_too_long=dict(type='str',),login=dict(type='str',),data_server_conn_fail=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/imap-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/imap-proxy"

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
        for k, v in payload["imap-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["imap-proxy"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["imap-proxy"][k] = v
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
    payload = build_json("imap-proxy", module)
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
    device_id = module.params["device_id"]

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
    
    if device_id:
        module.client.change_context(device_id)

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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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