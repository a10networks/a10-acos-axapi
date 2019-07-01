#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_smtp
description:
    - Show SMTP Statistics
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
                - "'all'= all; 'curr_proxy'= Current proxy conns; 'total_proxy'= Total proxy conns; 'request'= SMTP requests; 'request_success'= SMTP requests (success); 'no_proxy'= No proxy error; 'client_reset'= Client reset; 'server_reset'= Server reset; 'no_tuple'= No tuple error; 'parse_req_fail'= Parse request failure; 'server_select_fail'= Server selection failure; 'forward_req_fail'= Forward request failure; 'forward_req_data_fail'= Forward REQ data failure; 'req_retran'= Request retransmit; 'req_ofo'= Request pkt out-of-order; 'server_reselect'= Server reselection; 'server_prem_close'= Server premature close; 'new_server_conn'= Server connection made; 'snat_fail'= Source NAT failure; 'tcp_out_reset'= TCP out reset; 'recv_client_command_EHLO'= Recv client EHLO; 'recv_client_command_HELO'= Recv client HELO; 'recv_client_command_MAIL'= Recv client MAIL; 'recv_client_command_RCPT'= Recv client RCPT; 'recv_client_command_DATA'= Recv client DATA; 'recv_client_command_RSET'= Recv client RSET; 'recv_client_command_VRFY'= Recv client VRFY; 'recv_client_command_EXPN'= Recv client EXPN; 'recv_client_command_HELP'= Recv client HELP; 'recv_client_command_NOOP'= Recv client NOOP; 'recv_client_command_QUIT'= Recv client QUIT; 'recv_client_command_STARTTLS'= Recv client STARTTLS; 'recv_client_command_others'= Recv client other cmds; 'recv_server_service_not_ready'= Recv server serv-not-rdy; 'recv_server_unknow_reply_code'= Recv server unknown-code; 'send_client_service_ready'= Sent client serv-rdy; 'send_client_service_not_ready'= Sent client serv-not-rdy; 'send_client_close_connection'= Sent client close-conn; 'send_client_go_ahead'= Sent client go-ahead; 'send_client_start_TLS_first'= Sent client STARTTLS-1st; 'send_client_TLS_not_available'= Sent client TLS-not-aval; 'send_client_no_command'= Sent client no-such-cmd; 'send_server_cmd_reset'= Sent server RSET; 'TLS_established'= SSL session established; 'L4_switch'= L4 switching; 'Aflex_switch'= aFleX switching; 'Aflex_switch_ok'= aFleX switching (succ); 'client_domain_switch'= Client domain switching; 'client_domain_switch_ok'= Client domain sw (succ); 'LB_switch'= LB switching; 'LB_switch_ok'= LB switching (succ); 'read_request_line_fail'= Read request line fail; 'get_all_headers_fail'= Get all headers fail; 'too_many_headers'= Too many headers; 'line_too_long'= Line too long; 'line_across_packet'= Line across packets; 'line_extend'= Line extend; 'line_extend_fail'= Line extend fail; 'line_table_extend'= Table extend; 'line_table_extend_fail'= Table extend fail; 'parse_request_line_fail'= Parse request line fail; 'insert_resonse_line_fail'= Ins response line fail; 'remove_resonse_line_fail'= Del response line fail; 'parse_resonse_line_fail'= Parse response line fail; 'Aflex_lb_reselect'= aFleX lb reselect; 'Aflex_lb_reselect_ok'= aFleX lb reselect (succ); 'server_STARTTLS_init'= Init server side STARTTLS; 'server_STARTTLS_fail'= Server side STARTTLS fail; 'rserver_STARTTLS_disable'= real server not support STARTTLS; "
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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_proxy','total_proxy','request','request_success','no_proxy','client_reset','server_reset','no_tuple','parse_req_fail','server_select_fail','forward_req_fail','forward_req_data_fail','req_retran','req_ofo','server_reselect','server_prem_close','new_server_conn','snat_fail','tcp_out_reset','recv_client_command_EHLO','recv_client_command_HELO','recv_client_command_MAIL','recv_client_command_RCPT','recv_client_command_DATA','recv_client_command_RSET','recv_client_command_VRFY','recv_client_command_EXPN','recv_client_command_HELP','recv_client_command_NOOP','recv_client_command_QUIT','recv_client_command_STARTTLS','recv_client_command_others','recv_server_service_not_ready','recv_server_unknow_reply_code','send_client_service_ready','send_client_service_not_ready','send_client_close_connection','send_client_go_ahead','send_client_start_TLS_first','send_client_TLS_not_available','send_client_no_command','send_server_cmd_reset','TLS_established','L4_switch','Aflex_switch','Aflex_switch_ok','client_domain_switch','client_domain_switch_ok','LB_switch','LB_switch_ok','read_request_line_fail','get_all_headers_fail','too_many_headers','line_too_long','line_across_packet','line_extend','line_extend_fail','line_table_extend','line_table_extend_fail','parse_request_line_fail','insert_resonse_line_fail','remove_resonse_line_fail','parse_resonse_line_fail','Aflex_lb_reselect','Aflex_lb_reselect_ok','server_STARTTLS_init','server_STARTTLS_fail','rserver_STARTTLS_disable'])),
        uuid=dict(type='str',)
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

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("smtp", module)
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
    payload = build_json("smtp", module)
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
    payload = build_json("smtp", module)
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