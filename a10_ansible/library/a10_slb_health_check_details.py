#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_health_check_details
description:
    - Display Health Monitor Information for a given PIN and PID
short_description: Configures A10 slb.health-check-details
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - present
          - absent
          - noop
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
            rcv_integer:
                description:
                - "Field rcv_integer"
            domain:
                description:
                - "Field domain"
            curr_tcp_rtt:
                description:
                - "Field curr_tcp_rtt"
            force_up:
                description:
                - "Field force_up"
            postdata:
                description:
                - "Field postdata"
            starttls:
                description:
                - "Field starttls"
            received_fail:
                description:
                - "Field received_fail"
            sip_register:
                description:
                - "Field sip_register"
            community:
                description:
                - "Field community"
            dns_expect_type:
                description:
                - "Field dns_expect_type"
            attr_program:
                description:
                - "Field attr_program"
            avg_tcp_rtt:
                description:
                - "Field avg_tcp_rtt"
            pass:
                description:
                - "Field pass"
            query:
                description:
                - "Field query"
            rcpt_to:
                description:
                - "Field rcpt_to"
            response_timeout:
                description:
                - "Field response_timeout"
            health_state:
                description:
                - "Field health_state"
            expect_text_regex:
                description:
                - "Field expect_text_regex"
            state_reason:
                description:
                - "Field state_reason"
            dns_expect:
                description:
                - "Field dns_expect"
            attr_type:
                description:
                - "Field attr_type"
            user:
                description:
                - "Field user"
            ldap_tls:
                description:
                - "Field ldap_tls"
            ipaddr:
                description:
                - "Field ipaddr"
            monitor_name:
                description:
                - "Field monitor_name"
            send:
                description:
                - "Field send"
            half_open:
                description:
                - "Field half_open"
            kerberos_port:
                description:
                - "Field kerberos_port"
            secret:
                description:
                - "Field secret"
            curr_interval:
                description:
                - "Field curr_interval"
            dns_qtype:
                description:
                - "Field dns_qtype"
            mail_from:
                description:
                - "Field mail_from"
            kerberos_kdc:
                description:
                - "Field kerberos_kdc"
            method:
                description:
                - "Field method"
            arguments:
                description:
                - "Field arguments"
            expect_resp_code:
                description:
                - "Field expect_resp_code"
            kerberos_realm:
                description:
                - "Field kerberos_realm"
            l4_conn_num:
                description:
                - "Field l4_conn_num"
            oid:
                description:
                - "Field oid"
            attr_rpn:
                description:
                - "Field attr_rpn"
            http_errors:
                description:
                - "Field http_errors"
            expect_text:
                description:
                - "Field expect_text"
            db_column:
                description:
                - "Field db_column"
            attr_port:
                description:
                - "Field attr_port"
            expect_resp_regex_code:
                description:
                - "Field expect_resp_regex_code"
            status_code_rcv:
                description:
                - "Field status_code_rcv"
            pin_id:
                description:
                - "Field pin_id"
            ldap_ssl:
                description:
                - "Field ldap_ssl"
            tcp_only:
                description:
                - "Field tcp_only"
            maintenance_code:
                description:
                - "Field maintenance_code"
            resp_cont:
                description:
                - "Field resp_cont"
            url:
                description:
                - "Field url"
            process_index:
                description:
                - "Field process_index"
            snmp_operation:
                description:
                - "Field snmp_operation"
            mac_addr:
                description:
                - "Field mac_addr"
            host:
                description:
                - "Field host"
            curr_rtt:
                description:
                - "Field curr_rtt"
            receive:
                description:
                - "Field receive"
            avg_rtt:
                description:
                - "Field avg_rtt"
            http_wait_resp:
                description:
                - "Field http_wait_resp"
            l4_errors:
                description:
                - "Field l4_errors"
            db_name:
                description:
                - "Field db_name"
            http_req_sent:
                description:
                - "Field http_req_sent"
            pname:
                description:
                - "Field pname"
            transport_proto:
                description:
                - "Field transport_proto"
            dns_recurse:
                description:
                - "Field dns_recurse"
            db_row:
                description:
                - "Field db_row"
            base_dn:
                description:
                - "Field base_dn"
            received_success:
                description:
                - "Field received_success"
            attr_alias_addr:
                description:
                - "Field attr_alias_addr"
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
AVAILABLE_PROPERTIES = ["oper","uuid",]

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
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',rcv_integer=dict(type='int',),domain=dict(type='str',),curr_tcp_rtt=dict(type='int',),force_up=dict(type='int',),postdata=dict(type='str',),starttls=dict(type='int',),received_fail=dict(type='int',),sip_register=dict(type='int',),community=dict(type='str',),dns_expect_type=dict(type='int',),attr_program=dict(type='str',),avg_tcp_rtt=dict(type='int',),pass=dict(type='str',),query=dict(type='str',),rcpt_to=dict(type='str',),response_timeout=dict(type='int',),health_state=dict(type='str',),expect_text_regex=dict(type='str',),state_reason=dict(type='str',),dns_expect=dict(type='str',),attr_type=dict(type='str',),user=dict(type='str',),ldap_tls=dict(type='int',),ipaddr=dict(type='str',),monitor_name=dict(type='str',),send=dict(type='str',),half_open=dict(type='int',),kerberos_port=dict(type='int',),secret=dict(type='str',),curr_interval=dict(type='int',),dns_qtype=dict(type='int',),mail_from=dict(type='str',),kerberos_kdc=dict(type='str',),method=dict(type='str',),arguments=dict(type='str',),expect_resp_code=dict(type='str',),kerberos_realm=dict(type='str',),l4_conn_num=dict(type='int',),oid=dict(type='str',),attr_rpn=dict(type='str',),http_errors=dict(type='int',),expect_text=dict(type='str',),db_column=dict(type='int',),attr_port=dict(type='int',),expect_resp_regex_code=dict(type='str',),status_code_rcv=dict(type='int',),pin_id=dict(type='int',),ldap_ssl=dict(type='int',),tcp_only=dict(type='int',),maintenance_code=dict(type='str',),resp_cont=dict(type='str',),url=dict(type='str',),process_index=dict(type='int',),snmp_operation=dict(type='int',),mac_addr=dict(type='str',),host=dict(type='str',),curr_rtt=dict(type='int',),receive=dict(type='str',),avg_rtt=dict(type='int',),http_wait_resp=dict(type='int',),l4_errors=dict(type='int',),db_name=dict(type='str',),http_req_sent=dict(type='int',),pname=dict(type='str',),transport_proto=dict(type='int',),dns_recurse=dict(type='int',),db_row=dict(type='int',),base_dn=dict(type='str',),received_success=dict(type='int',),attr_alias_addr=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/health-check-details"

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
    url_base = "/axapi/v3/slb/health-check-details"

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

def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result

def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config):
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)

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