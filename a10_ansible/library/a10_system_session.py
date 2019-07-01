#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_system_session
description:
    - Session Entries
short_description: Configures A10 system.session
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
                - "'all'= all; 'total_l4_conn'= Total L4 Count; 'conn_counter'= Conn Count; 'conn_freed_counter'= Conn Freed; 'total_l4_packet_count'= Total L4 Packet Count; 'total_l7_packet_count'= Total L7 Packet Count; 'total_l4_conn_proxy'= Total L4 Conn Proxy Count; 'total_l7_conn'= Total L7 Conn; 'total_tcp_conn'= Total TCP Conn; 'curr_free_conn'= Curr Free Conn; 'tcp_est_counter'= TCP Established; 'tcp_half_open_counter'= TCP Half Open; 'tcp_half_close_counter'= TCP Half Closed; 'udp_counter'= UDP Count; 'ip_counter'= IP Count; 'other_counter'= Non TCP/UDP IP sessions; 'reverse_nat_tcp_counter'= Reverse NAT TCP; 'reverse_nat_udp_counter'= Reverse NAT UDP; 'tcp_syn_half_open_counter'= TCP SYN Half Open; 'conn_smp_alloc_counter'= Conn SMP Alloc; 'conn_smp_free_counter'= Conn SMP Free; 'conn_smp_aged_counter'= Conn SMP Aged; 'ssl_count_curr'= Curr SSL Count; 'ssl_count_total'= Total SSL Count; 'server_ssl_count_curr'= Current SSL Server Count; 'server_ssl_count_total'= Total SSL Server Count; 'client_ssl_reuse_total'= Total SSL Client Reuse; 'server_ssl_reuse_total'= Total SSL Server Reuse; 'ssl_failed_total'= Total SSL Failures; 'ssl_failed_ca_verification'= SSL Cert Auth Verification Errors; 'ssl_server_cert_error'= SSL Server Cert Errors; 'ssl_client_cert_auth_fail'= SSL Client Cert Auth Failures; 'total_ip_nat_conn'= Total IP Nat Conn; 'total_l2l3_conn'= Totl L2/L3 Connections; 'client_ssl_ctx_malloc_failure'= Client SSL Ctx malloc Failures; 'conn_type_0_available'= Conn Type 0 Available; 'conn_type_1_available'= Conn Type 1 Available; 'conn_type_2_available'= Conn Type 2 Available; 'conn_type_3_available'= Conn Type 3 Available; 'conn_type_4_available'= Conn Type 4 Available; 'conn_smp_type_0_available'= Conn SMP Type 0 Available; 'conn_smp_type_1_available'= Conn SMP Type 1 Available; 'conn_smp_type_2_available'= Conn SMP Type 2 Available; 'conn_smp_type_3_available'= Conn SMP Type 3 Available; 'conn_smp_type_4_available'= Conn SMP Type 4 Available; 'sctp-half-open-counter'= SCTP Half Open; 'sctp-est-counter'= SCTP Established; 'nonssl_bypass'= NON SSL Bypass Count; 'ssl_failsafe_total'= Total SSL Failsafe Count; 'ssl_forward_proxy_failed_handshake_total'= Total SSL Forward Proxy Failed Handshake Count; 'ssl_forward_proxy_failed_tcp_total'= Total SSL Forward Proxy Failed TCP Count; 'ssl_forward_proxy_failed_crypto_total'= Total SSL Forward Proxy Failed Crypto Count; 'ssl_forward_proxy_failed_cert_verify_total'= Total SSL Forward Proxy Failed Certificate Verification Count; 'ssl_forward_proxy_invalid_ocsp_stapling_total'= Total SSL Forward Proxy Invalid OCSP Stapling Count; 'ssl_forward_proxy_revoked_ocsp_total'= Total SSL Forward Proxy Revoked OCSP Response Count; 'ssl_forward_proxy_failed_cert_signing_total'= Total SSL Forward Proxy Failed Certificate Signing Count; 'ssl_forward_proxy_failed_ssl_version_total'= Total SSL Forward Proxy Unsupported version Count; 'ssl_forward_proxy_sni_bypass_total'= Total SSL Forward Proxy SNI Bypass Count; 'ssl_forward_proxy_client_auth_bypass_total'= Total SSL Forward Proxy Client Auth Bypass Count; 'conn_app_smp_alloc_counter'= Conn APP SMP Alloc; 'diameter_conn_counter'= Diameter Conn Count; 'diameter_conn_freed_counter'= Diameter Conn Freed; 'debug_tcp_counter'= Hidden TCP sessions for CGNv6 Stateless Technologies; 'debug_udp_counter'= Hidden UDP sessions for CGNv6 Stateless Technologies; 'total_fw_conn'= Total Firewall Conn; 'total_local_conn'= Total Local Conn; 'total_curr_conn'= Total Curr Conn; 'client_ssl_fatal_alert'= client ssl fatal alert; 'client_ssl_fin_rst'= client ssl fin rst; 'fp_session_fin_rst'= FP Session FIN/RST; 'server_ssl_fatal_alert'= server ssl fatal alert; 'server_ssl_fin_rst'= server ssl fin rst; 'client_template_int_err'= client template internal error; 'client_template_unknown_err'= client template unknown error; 'server_template_int_err'= server template int error; 'server_template_unknown_err'= server template unknown error; "
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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_l4_conn','conn_counter','conn_freed_counter','total_l4_packet_count','total_l7_packet_count','total_l4_conn_proxy','total_l7_conn','total_tcp_conn','curr_free_conn','tcp_est_counter','tcp_half_open_counter','tcp_half_close_counter','udp_counter','ip_counter','other_counter','reverse_nat_tcp_counter','reverse_nat_udp_counter','tcp_syn_half_open_counter','conn_smp_alloc_counter','conn_smp_free_counter','conn_smp_aged_counter','ssl_count_curr','ssl_count_total','server_ssl_count_curr','server_ssl_count_total','client_ssl_reuse_total','server_ssl_reuse_total','ssl_failed_total','ssl_failed_ca_verification','ssl_server_cert_error','ssl_client_cert_auth_fail','total_ip_nat_conn','total_l2l3_conn','client_ssl_ctx_malloc_failure','conn_type_0_available','conn_type_1_available','conn_type_2_available','conn_type_3_available','conn_type_4_available','conn_smp_type_0_available','conn_smp_type_1_available','conn_smp_type_2_available','conn_smp_type_3_available','conn_smp_type_4_available','sctp-half-open-counter','sctp-est-counter','nonssl_bypass','ssl_failsafe_total','ssl_forward_proxy_failed_handshake_total','ssl_forward_proxy_failed_tcp_total','ssl_forward_proxy_failed_crypto_total','ssl_forward_proxy_failed_cert_verify_total','ssl_forward_proxy_invalid_ocsp_stapling_total','ssl_forward_proxy_revoked_ocsp_total','ssl_forward_proxy_failed_cert_signing_total','ssl_forward_proxy_failed_ssl_version_total','ssl_forward_proxy_sni_bypass_total','ssl_forward_proxy_client_auth_bypass_total','conn_app_smp_alloc_counter','diameter_conn_counter','diameter_conn_freed_counter','debug_tcp_counter','debug_udp_counter','total_fw_conn','total_local_conn','total_curr_conn','client_ssl_fatal_alert','client_ssl_fin_rst','fp_session_fin_rst','server_ssl_fatal_alert','server_ssl_fin_rst','client_template_int_err','client_template_unknown_err','server_template_int_err','server_template_unknown_err'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/session"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/session"

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
    payload = build_json("session", module)
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
    payload = build_json("session", module)
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
    payload = build_json("session", module)
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