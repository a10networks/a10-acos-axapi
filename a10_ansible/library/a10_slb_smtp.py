#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_smtp
description:
    - Configure SMTP
short_description: Configures A10 slb.smtp
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
            cpu_count:
                description:
                - "Field cpu_count"
            smtp_cpu_list:
                description:
                - "Field smtp_cpu_list"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Current proxy conns; 'total_proxy'= Total proxy conns; 'request'= SMTP requests; 'request_success'= SMTP requests (success); 'no_proxy'= No proxy error; 'client_reset'= Client reset; 'server_reset'= Server reset; 'no_tuple'= No tuple error; 'parse_req_fail'= Parse request failure; 'server_select_fail'= Server selection failure; 'forward_req_fail'= Forward request failure; 'forward_req_data_fail'= Forward REQ data failure; 'req_retran'= Request retransmit; 'req_ofo'= Request pkt out-of-order; 'server_reselect'= Server reselection; 'server_prem_close'= Server premature close; 'new_server_conn'= Server connection made; 'snat_fail'= Source NAT failure; 'tcp_out_reset'= TCP out reset; 'recv_client_command_EHLO'= Recv client EHLO; 'recv_client_command_HELO'= Recv client HELO; 'recv_client_command_MAIL'= Recv client MAIL; 'recv_client_command_RCPT'= Recv client RCPT; 'recv_client_command_DATA'= Recv client DATA; 'recv_client_command_RSET'= Recv client RSET; 'recv_client_command_VRFY'= Recv client VRFY; 'recv_client_command_EXPN'= Recv client EXPN; 'recv_client_command_HELP'= Recv client HELP; 'recv_client_command_NOOP'= Recv client NOOP; 'recv_client_command_QUIT'= Recv client QUIT; 'recv_client_command_STARTTLS'= Recv client STARTTLS; 'recv_client_command_others'= Recv client other cmds; 'recv_server_service_not_ready'= Recv server serv-not-rdy; 'recv_server_unknow_reply_code'= Recv server unknown-code; 'send_client_service_ready'= Sent client serv-rdy; 'send_client_service_not_ready'= Sent client serv-not-rdy; 'send_client_close_connection'= Sent client close-conn; 'send_client_go_ahead'= Sent client go-ahead; 'send_client_start_TLS_first'= Sent client STARTTLS-1st; 'send_client_TLS_not_available'= Sent client TLS-not-aval; 'send_client_no_command'= Sent client no-such-cmd; 'send_server_cmd_reset'= Sent server RSET; 'TLS_established'= SSL session established; 'L4_switch'= L4 switching; 'Aflex_switch'= aFleX switching; 'Aflex_switch_ok'= aFleX switching (succ); 'client_domain_switch'= Client domain switching; 'client_domain_switch_ok'= Client domain sw (succ); 'LB_switch'= LB switching; 'LB_switch_ok'= LB switching (succ); 'read_request_line_fail'= Read request line fail; 'get_all_headers_fail'= Get all headers fail; 'too_many_headers'= Too many headers; 'line_too_long'= Line too long; 'line_across_packet'= Line across packets; 'line_extend'= Line extend; 'line_extend_fail'= Line extend fail; 'line_table_extend'= Table extend; 'line_table_extend_fail'= Table extend fail; 'parse_request_line_fail'= Parse request line fail; 'insert_resonse_line_fail'= Ins response line fail; 'remove_resonse_line_fail'= Del response line fail; 'parse_resonse_line_fail'= Parse response line fail; 'Aflex_lb_reselect'= aFleX lb reselect; 'Aflex_lb_reselect_ok'= aFleX lb reselect (succ); 'server_STARTTLS_init'= Init server side STARTTLS; 'server_STARTTLS_fail'= Server side STARTTLS fail; 'rserver_STARTTLS_disable'= real server not support STARTTLS; 'recv_client_command_TURN'= Recv client TURN; 'recv_client_command_ETRN'= Recv client ETRN; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            request_success:
                description:
                - "SMTP requests (success)"
            recv_client_command_RCPT:
                description:
                - "Recv client RCPT"
            recv_client_command_ETRN:
                description:
                - "Recv client ETRN"
            forward_req_fail:
                description:
                - "Forward request failure"
            recv_server_unknow_reply_code:
                description:
                - "Recv server unknown-code"
            total_proxy:
                description:
                - "Total proxy conns"
            L4_switch:
                description:
                - "L4 switching"
            too_many_headers:
                description:
                - "Too many headers"
            recv_client_command_QUIT:
                description:
                - "Recv client QUIT"
            recv_client_command_NOOP:
                description:
                - "Recv client NOOP"
            new_server_conn:
                description:
                - "Server connection made"
            req_retran:
                description:
                - "Request retransmit"
            server_reselect:
                description:
                - "Server reselection"
            recv_client_command_MAIL:
                description:
                - "Recv client MAIL"
            send_client_start_TLS_first:
                description:
                - "Sent client STARTTLS-1st"
            recv_client_command_VRFY:
                description:
                - "Recv client VRFY"
            server_prem_close:
                description:
                - "Server premature close"
            parse_resonse_line_fail:
                description:
                - "Parse response line fail"
            send_client_close_connection:
                description:
                - "Sent client close-conn"
            forward_req_data_fail:
                description:
                - "Forward REQ data failure"
            recv_client_command_HELO:
                description:
                - "Recv client HELO"
            no_proxy:
                description:
                - "No proxy error"
            client_reset:
                description:
                - "Client reset"
            line_across_packet:
                description:
                - "Line across packets"
            server_STARTTLS_init:
                description:
                - "Init server side STARTTLS"
            recv_client_command_HELP:
                description:
                - "Recv client HELP"
            client_domain_switch_ok:
                description:
                - "Client domain sw (succ)"
            recv_client_command_RSET:
                description:
                - "Recv client RSET"
            recv_client_command_STARTTLS:
                description:
                - "Recv client STARTTLS"
            recv_client_command_others:
                description:
                - "Recv client other cmds"
            recv_client_command_EXPN:
                description:
                - "Recv client EXPN"
            LB_switch:
                description:
                - "LB switching"
            no_tuple:
                description:
                - "No tuple error"
            send_client_no_command:
                description:
                - "Sent client no-such-cmd"
            Aflex_switch_ok:
                description:
                - "aFleX switching (succ)"
            rserver_STARTTLS_disable:
                description:
                - "real server not support STARTTLS"
            server_select_fail:
                description:
                - "Server selection failure"
            tcp_out_reset:
                description:
                - "TCP out reset"
            line_table_extend:
                description:
                - "Table extend"
            send_server_cmd_reset:
                description:
                - "Sent server RSET"
            line_extend_fail:
                description:
                - "Line extend fail"
            recv_client_command_DATA:
                description:
                - "Recv client DATA"
            Aflex_lb_reselect:
                description:
                - "aFleX lb reselect"
            curr_proxy:
                description:
                - "Current proxy conns"
            send_client_service_ready:
                description:
                - "Sent client serv-rdy"
            send_client_go_ahead:
                description:
                - "Sent client go-ahead"
            req_ofo:
                description:
                - "Request pkt out-of-order"
            client_domain_switch:
                description:
                - "Client domain switching"
            server_reset:
                description:
                - "Server reset"
            snat_fail:
                description:
                - "Source NAT failure"
            recv_server_service_not_ready:
                description:
                - "Recv server serv-not-rdy"
            parse_request_line_fail:
                description:
                - "Parse request line fail"
            remove_resonse_line_fail:
                description:
                - "Del response line fail"
            line_table_extend_fail:
                description:
                - "Table extend fail"
            get_all_headers_fail:
                description:
                - "Get all headers fail"
            parse_req_fail:
                description:
                - "Parse request failure"
            LB_switch_ok:
                description:
                - "LB switching (succ)"
            Aflex_switch:
                description:
                - "aFleX switching"
            send_client_service_not_ready:
                description:
                - "Sent client serv-not-rdy"
            line_too_long:
                description:
                - "Line too long"
            request:
                description:
                - "SMTP requests"
            line_extend:
                description:
                - "Line extend"
            Aflex_lb_reselect_ok:
                description:
                - "aFleX lb reselect (succ)"
            server_STARTTLS_fail:
                description:
                - "Server side STARTTLS fail"
            recv_client_command_EHLO:
                description:
                - "Recv client EHLO"
            insert_resonse_line_fail:
                description:
                - "Ins response line fail"
            send_client_TLS_not_available:
                description:
                - "Sent client TLS-not-aval"
            read_request_line_fail:
                description:
                - "Read request line fail"
            recv_client_command_TURN:
                description:
                - "Recv client TURN"
            TLS_established:
                description:
                - "SSL session established"
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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', cpu_count=dict(type='int', ),smtp_cpu_list=dict(type='list', request_success=dict(type='int', ),recv_client_command_RCPT=dict(type='int', ),recv_client_command_ETRN=dict(type='int', ),forward_req_fail=dict(type='int', ),recv_server_unknow_reply_code=dict(type='int', ),total_proxy=dict(type='int', ),L4_switch=dict(type='int', ),too_many_headers=dict(type='int', ),recv_client_command_QUIT=dict(type='int', ),recv_client_command_NOOP=dict(type='int', ),new_server_conn=dict(type='int', ),req_retran=dict(type='int', ),server_reselect=dict(type='int', ),recv_client_command_MAIL=dict(type='int', ),send_client_start_TLS_first=dict(type='int', ),recv_client_command_VRFY=dict(type='int', ),server_prem_close=dict(type='int', ),parse_resonse_line_fail=dict(type='int', ),send_client_close_connection=dict(type='int', ),forward_req_data_fail=dict(type='int', ),recv_client_command_HELO=dict(type='int', ),no_proxy=dict(type='int', ),client_reset=dict(type='int', ),line_across_packet=dict(type='int', ),server_STARTTLS_init=dict(type='int', ),recv_client_command_HELP=dict(type='int', ),client_domain_switch_ok=dict(type='int', ),recv_client_command_RSET=dict(type='int', ),recv_client_command_STARTTLS=dict(type='int', ),recv_client_command_others=dict(type='int', ),recv_client_command_EXPN=dict(type='int', ),LB_switch=dict(type='int', ),no_tuple=dict(type='int', ),send_client_no_command=dict(type='int', ),Aflex_switch_ok=dict(type='int', ),rserver_STARTTLS_disable=dict(type='int', ),server_select_fail=dict(type='int', ),tcp_out_reset=dict(type='int', ),line_table_extend=dict(type='int', ),send_server_cmd_reset=dict(type='int', ),line_extend_fail=dict(type='int', ),recv_client_command_DATA=dict(type='int', ),Aflex_lb_reselect=dict(type='int', ),curr_proxy=dict(type='int', ),send_client_service_ready=dict(type='int', ),send_client_go_ahead=dict(type='int', ),req_ofo=dict(type='int', ),client_domain_switch=dict(type='int', ),server_reset=dict(type='int', ),snat_fail=dict(type='int', ),recv_server_service_not_ready=dict(type='int', ),parse_request_line_fail=dict(type='int', ),remove_resonse_line_fail=dict(type='int', ),line_table_extend_fail=dict(type='int', ),get_all_headers_fail=dict(type='int', ),parse_req_fail=dict(type='int', ),LB_switch_ok=dict(type='int', ),Aflex_switch=dict(type='int', ),send_client_service_not_ready=dict(type='int', ),line_too_long=dict(type='int', ),request=dict(type='int', ),line_extend=dict(type='int', ),Aflex_lb_reselect_ok=dict(type='int', ),server_STARTTLS_fail=dict(type='int', ),recv_client_command_EHLO=dict(type='int', ),insert_resonse_line_fail=dict(type='int', ),send_client_TLS_not_available=dict(type='int', ),read_request_line_fail=dict(type='int', ),recv_client_command_TURN=dict(type='int', ),TLS_established=dict(type='int', ))),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','curr_proxy','total_proxy','request','request_success','no_proxy','client_reset','server_reset','no_tuple','parse_req_fail','server_select_fail','forward_req_fail','forward_req_data_fail','req_retran','req_ofo','server_reselect','server_prem_close','new_server_conn','snat_fail','tcp_out_reset','recv_client_command_EHLO','recv_client_command_HELO','recv_client_command_MAIL','recv_client_command_RCPT','recv_client_command_DATA','recv_client_command_RSET','recv_client_command_VRFY','recv_client_command_EXPN','recv_client_command_HELP','recv_client_command_NOOP','recv_client_command_QUIT','recv_client_command_STARTTLS','recv_client_command_others','recv_server_service_not_ready','recv_server_unknow_reply_code','send_client_service_ready','send_client_service_not_ready','send_client_close_connection','send_client_go_ahead','send_client_start_TLS_first','send_client_TLS_not_available','send_client_no_command','send_server_cmd_reset','TLS_established','L4_switch','Aflex_switch','Aflex_switch_ok','client_domain_switch','client_domain_switch_ok','LB_switch','LB_switch_ok','read_request_line_fail','get_all_headers_fail','too_many_headers','line_too_long','line_across_packet','line_extend','line_extend_fail','line_table_extend','line_table_extend_fail','parse_request_line_fail','insert_resonse_line_fail','remove_resonse_line_fail','parse_resonse_line_fail','Aflex_lb_reselect','Aflex_lb_reselect_ok','server_STARTTLS_init','server_STARTTLS_fail','rserver_STARTTLS_disable','recv_client_command_TURN','recv_client_command_ETRN'])),
        stats=dict(type='dict', request_success=dict(type='str', ),recv_client_command_RCPT=dict(type='str', ),recv_client_command_ETRN=dict(type='str', ),forward_req_fail=dict(type='str', ),recv_server_unknow_reply_code=dict(type='str', ),total_proxy=dict(type='str', ),L4_switch=dict(type='str', ),too_many_headers=dict(type='str', ),recv_client_command_QUIT=dict(type='str', ),recv_client_command_NOOP=dict(type='str', ),new_server_conn=dict(type='str', ),req_retran=dict(type='str', ),server_reselect=dict(type='str', ),recv_client_command_MAIL=dict(type='str', ),send_client_start_TLS_first=dict(type='str', ),recv_client_command_VRFY=dict(type='str', ),server_prem_close=dict(type='str', ),parse_resonse_line_fail=dict(type='str', ),send_client_close_connection=dict(type='str', ),forward_req_data_fail=dict(type='str', ),recv_client_command_HELO=dict(type='str', ),no_proxy=dict(type='str', ),client_reset=dict(type='str', ),line_across_packet=dict(type='str', ),server_STARTTLS_init=dict(type='str', ),recv_client_command_HELP=dict(type='str', ),client_domain_switch_ok=dict(type='str', ),recv_client_command_RSET=dict(type='str', ),recv_client_command_STARTTLS=dict(type='str', ),recv_client_command_others=dict(type='str', ),recv_client_command_EXPN=dict(type='str', ),LB_switch=dict(type='str', ),no_tuple=dict(type='str', ),send_client_no_command=dict(type='str', ),Aflex_switch_ok=dict(type='str', ),rserver_STARTTLS_disable=dict(type='str', ),server_select_fail=dict(type='str', ),tcp_out_reset=dict(type='str', ),line_table_extend=dict(type='str', ),send_server_cmd_reset=dict(type='str', ),line_extend_fail=dict(type='str', ),recv_client_command_DATA=dict(type='str', ),Aflex_lb_reselect=dict(type='str', ),curr_proxy=dict(type='str', ),send_client_service_ready=dict(type='str', ),send_client_go_ahead=dict(type='str', ),req_ofo=dict(type='str', ),client_domain_switch=dict(type='str', ),server_reset=dict(type='str', ),snat_fail=dict(type='str', ),recv_server_service_not_ready=dict(type='str', ),parse_request_line_fail=dict(type='str', ),remove_resonse_line_fail=dict(type='str', ),line_table_extend_fail=dict(type='str', ),get_all_headers_fail=dict(type='str', ),parse_req_fail=dict(type='str', ),LB_switch_ok=dict(type='str', ),Aflex_switch=dict(type='str', ),send_client_service_not_ready=dict(type='str', ),line_too_long=dict(type='str', ),request=dict(type='str', ),line_extend=dict(type='str', ),Aflex_lb_reselect_ok=dict(type='str', ),server_STARTTLS_fail=dict(type='str', ),recv_client_command_EHLO=dict(type='str', ),insert_resonse_line_fail=dict(type='str', ),send_client_TLS_not_available=dict(type='str', ),read_request_line_fail=dict(type='str', ),recv_client_command_TURN=dict(type='str', ),TLS_established=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/smtp"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/smtp"

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
        for k, v in payload["smtp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["smtp"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["smtp"][k] = v
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
    payload = build_json("smtp", module)
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
    a10_device_context_id = module.params["a10_device_context_id"]

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