#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_health_monitor
description:
    - Define the Health Monitor object
short_description: Configures A10 health.monitor
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
    override_ipv4:
        description:
        - "Override implicitly inherited IPv4 address from target"
        required: False
    override_ipv6:
        description:
        - "Override implicitly inherited IPv6 address from target"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    ssl_ciphers:
        description:
        - "Specify OpenSSL Cipher Suite name(s) for Health check (OpenSSL Cipher Suite(s) (Eg= AES128-SHA256), if the cipher is invalid, would give information at HM down reason)"
        required: False
    strict_retry_on_server_err_resp:
        description:
        - "Require strictly retry"
        required: False
    passive_interval:
        description:
        - "Interval to do manual health checking while in passive mode (Specify value in seconds (Default is 10 s))"
        required: False
    override_port:
        description:
        - "Override implicitly inherited port from target (Port number (1-65534))"
        required: False
    up_retry:
        description:
        - "Specify the Healthcheck Retries before declaring target up (Up-retry count (default 1))"
        required: False
    interval:
        description:
        - "Specify the Healthcheck Interval (Interval Value, in seconds (default 5))"
        required: False
    sample_threshold:
        description:
        - "Number of samples in one epoch above which passive HC is enabled. If below or equal to the threshold, passive HC is disabled (Specify number of samples in one second (Default is 50). If the number of samples is 0, no action is taken)"
        required: False
    retry:
        description:
        - "Specify the Healthcheck Retries (Retry Count (default 3))"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    timeout:
        description:
        - "Specify the Healthcheck Timeout (Timeout Value, in seconds(default 5), Timeout should be less than or equal to interval)"
        required: False
    passive:
        description:
        - "Specify passive mode"
        required: False
    threshold:
        description:
        - "Threshold percentage above which passive mode is enabled (Specify percentage (Default is 75%))"
        required: False
    dsr_l2_strict:
        description:
        - "Enable strict L2dsr health-check"
        required: False
    status_code:
        description:
        - "'status-code-2xx'= Enable passive mode with 2xx http status code; 'status-code-non-5xx'= Enable passive mode with non-5xx http status code; "
        required: False
    disable_after_down:
        description:
        - "Disable the target if health check failed"
        required: False
    method:
        description:
        - "Field method"
        required: False
        suboptions:
            ftp:
                description:
                - "Field ftp"
            udp:
                description:
                - "Field udp"
            sip:
                description:
                - "Field sip"
            http:
                description:
                - "Field http"
            dns:
                description:
                - "Field dns"
            database:
                description:
                - "Field database"
            ntp:
                description:
                - "Field ntp"
            icmp:
                description:
                - "Field icmp"
            rtsp:
                description:
                - "Field rtsp"
            smtp:
                description:
                - "Field smtp"
            tcp:
                description:
                - "Field tcp"
            pop3:
                description:
                - "Field pop3"
            tacplus:
                description:
                - "Field tacplus"
            radius:
                description:
                - "Field radius"
            external:
                description:
                - "Field external"
            https:
                description:
                - "Field https"
            compound:
                description:
                - "Field compound"
            ldap:
                description:
                - "Field ldap"
            snmp:
                description:
                - "Field snmp"
            kerberos_kdc:
                description:
                - "Field kerberos_kdc"
            imap:
                description:
                - "Field imap"
    name:
        description:
        - "Monitor Name"
        required: True


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["disable_after_down","dsr_l2_strict","interval","method","name","override_ipv4","override_ipv6","override_port","passive","passive_interval","retry","sample_threshold","ssl_ciphers","status_code","strict_retry_on_server_err_resp","threshold","timeout","up_retry","user_tag","uuid",]

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
        override_ipv4=dict(type='str',),
        override_ipv6=dict(type='str',),
        uuid=dict(type='str',),
        ssl_ciphers=dict(type='str',),
        strict_retry_on_server_err_resp=dict(type='bool',),
        passive_interval=dict(type='int',),
        override_port=dict(type='int',),
        up_retry=dict(type='int',),
        interval=dict(type='int',),
        sample_threshold=dict(type='int',),
        retry=dict(type='int',),
        user_tag=dict(type='str',),
        timeout=dict(type='int',),
        passive=dict(type='bool',),
        threshold=dict(type='int',),
        dsr_l2_strict=dict(type='bool',),
        status_code=dict(type='str',choices=['status-code-2xx','status-code-non-5xx']),
        disable_after_down=dict(type='bool',),
        method=dict(type='dict',ftp=dict(type='dict',ftp=dict(type='bool',),uuid=dict(type='str',),ftp_password_string=dict(type='str',),ftp_password=dict(type='bool',),ftp_port=dict(type='int',),ftp_encrypted=dict(type='str',),ftp_username=dict(type='str',)),udp=dict(type='dict',udp=dict(type='bool',),uuid=dict(type='str',),force_up_with_single_healthcheck=dict(type='bool',),udp_port=dict(type='int',)),sip=dict(type='dict',sip=dict(type='bool',),uuid=dict(type='str',),register=dict(type='bool',),expect_response_code=dict(type='str',),sip_port=dict(type='int',),sip_tcp=dict(type='bool',)),http=dict(type='dict',http_url=dict(type='bool',),text_regex=dict(type='str',),http_maintenance_code=dict(type='str',),http_kerberos_auth=dict(type='bool',),http_postfile=dict(type='str',),response_code_regex=dict(type='str',),uuid=dict(type='str',),post_type=dict(type='str',choices=['postdata','postfile']),http_password_string=dict(type='str',),url_path=dict(type='str',),http_response_code=dict(type='str',),http_host=dict(type='str',),http=dict(type='bool',),url_type=dict(type='str',choices=['GET','POST','HEAD']),http_postdata=dict(type='str',),http_text=dict(type='str',),http_encrypted=dict(type='str',),http_kerberos_realm=dict(type='str',),http_password=dict(type='bool',),http_kerberos_kdc=dict(type='dict',http_kerberos_hostipv6=dict(type='str',),http_kerberos_port=dict(type='int',),http_kerberos_portv6=dict(type='int',),http_kerberos_hostip=dict(type='str',)),http_expect=dict(type='bool',),post_path=dict(type='str',),http_username=dict(type='str',),http_port=dict(type='int',)),dns=dict(type='dict',dns_domain_type=dict(type='str',choices=['A','CNAME','SOA','PTR','MX','TXT','AAAA']),dns_ipv4_recurse=dict(type='str',choices=['enabled','disabled']),uuid=dict(type='str',),dns_ipv6_port=dict(type='int',),dns_ipv4_addr=dict(type='str',),dns_domain_expect=dict(type='dict',dns_domain_response=dict(type='str',)),dns_ipv4_expect=dict(type='dict',dns_ipv4_response=dict(type='str',)),dns_ipv4_port=dict(type='int',),dns_ipv6_expect=dict(type='dict',dns_ipv6_response=dict(type='str',)),dns_ip_key=dict(type='bool',),dns_ipv6_recurse=dict(type='str',choices=['enabled','disabled']),dns_ipv6_tcp=dict(type='bool',),dns_domain_recurse=dict(type='str',choices=['enabled','disabled']),dns_domain_tcp=dict(type='bool',),dns=dict(type='bool',),dns_ipv4_tcp=dict(type='bool',),dns_domain=dict(type='str',),dns_ipv6_addr=dict(type='str',),dns_domain_port=dict(type='int',)),database=dict(type='dict',db_send=dict(type='str',),db_password=dict(type='bool',),uuid=dict(type='str',),db_encrypted=dict(type='str',),database=dict(type='bool',),database_name=dict(type='str',choices=['mssql','mysql','oracle','postgresql']),db_row_integer=dict(type='int',),db_receive=dict(type='str',),db_receive_integer=dict(type='int',),db_password_str=dict(type='str',),db_column=dict(type='int',),db_name=dict(type='str',),db_column_integer=dict(type='int',),db_username=dict(type='str',),db_row=dict(type='int',)),ntp=dict(type='dict',ntp=dict(type='bool',),uuid=dict(type='str',),ntp_port=dict(type='int',)),icmp=dict(type='dict',ip=dict(type='str',),icmp=dict(type='bool',),uuid=dict(type='str',),ipv6=dict(type='str',),transparent=dict(type='bool',)),rtsp=dict(type='dict',rtsp_port=dict(type='int',),rtsp=dict(type='bool',),rtspurl=dict(type='str',),uuid=dict(type='str',)),smtp=dict(type='dict',smtp_port=dict(type='int',),smtp_starttls=dict(type='bool',),uuid=dict(type='str',),smtp_domain=dict(type='str',),smtp=dict(type='bool',),mail_from=dict(type='str',),rcpt_to=dict(type='str',)),tcp=dict(type='dict',uuid=dict(type='str',),tcp_port=dict(type='int',),port_resp=dict(type='dict',port_contains=dict(type='str',)),method_tcp=dict(type='bool',),port_send=dict(type='str',),port_halfopen=dict(type='bool',)),pop3=dict(type='dict',pop3_password_string=dict(type='str',),uuid=dict(type='str',),pop3_password=dict(type='bool',),pop3_username=dict(type='str',),pop3_encrypted=dict(type='str',),pop3=dict(type='bool',),pop3_port=dict(type='int',)),tacplus=dict(type='dict',tacplus_encrypted=dict(type='str',),secret_encrypted=dict(type='str',),uuid=dict(type='str',),tacplus_password_string=dict(type='str',),tacplus_secret=dict(type='bool',),tacplus_username=dict(type='str',),tacplus=dict(type='bool',),tacplus_secret_string=dict(type='str',),tacplus_type=dict(type='str',choices=['inbound-ascii-login']),tacplus_password=dict(type='bool',),tacplus_port=dict(type='int',)),radius=dict(type='dict',radius_username=dict(type='str',),radius_password_string=dict(type='str',),radius_encrypted=dict(type='str',),radius_response_code=dict(type='str',),radius_expect=dict(type='bool',),radius=dict(type='bool',),radius_secret=dict(type='str',),radius_password=dict(type='bool',),radius_port=dict(type='int',),uuid=dict(type='str',)),external=dict(type='dict',uuid=dict(type='str',),external=dict(type='bool',),ext_preference=dict(type='bool',),ext_arguments=dict(type='str',),shared_partition_program=dict(type='bool',),ext_port=dict(type='int',),ext_program_shared=dict(type='str',),ext_program=dict(type='str',)),https=dict(type='dict',https_kerberos_realm=dict(type='str',),cert_key_shared=dict(type='bool',),response_code_regex=dict(type='str',),uuid=dict(type='str',),post_type=dict(type='str',choices=['postdata','postfile']),https_kerberos_auth=dict(type='bool',),https_username=dict(type='str',),key_phrase=dict(type='str',),https_postdata=dict(type='str',),https_key_encrypted=dict(type='str',),https_expect=dict(type='bool',),https=dict(type='bool',),text_regex=dict(type='str',),https_host=dict(type='str',),key_pass_phrase=dict(type='bool',),https_encrypted=dict(type='str',),url_type=dict(type='str',choices=['GET','POST','HEAD']),web_port=dict(type='int',),disable_sslv2hello=dict(type='bool',),https_kerberos_kdc=dict(type='dict',https_kerberos_hostip=dict(type='str',),https_kerberos_port=dict(type='int',),https_kerberos_portv6=dict(type='int',),https_kerberos_hostipv6=dict(type='str',)),key=dict(type='str',),https_password_string=dict(type='str',),post_path=dict(type='str',),https_postfile=dict(type='str',),https_password=dict(type='bool',),cert=dict(type='str',),https_text=dict(type='str',),https_response_code=dict(type='str',),url_path=dict(type='str',),https_maintenance_code=dict(type='str',),https_url=dict(type='bool',)),compound=dict(type='dict',rpn_string=dict(type='str',),uuid=dict(type='str',),compound=dict(type='bool',)),ldap=dict(type='dict',AcceptResRef=dict(type='bool',),ldap_port=dict(type='int',),uuid=dict(type='str',),ldap_password_string=dict(type='str',),ldap_encrypted=dict(type='str',),BaseDN=dict(type='str',),ldap_password=dict(type='bool',),ldap_binddn=dict(type='str',),ldap_query=dict(type='str',),ldap_security=dict(type='str',choices=['overssl','StartTLS']),ldap=dict(type='bool',),ldap_run_search=dict(type='bool',),AcceptNotFound=dict(type='bool',)),snmp=dict(type='dict',snmp_port=dict(type='int',),uuid=dict(type='str',),oid=dict(type='dict',mib=dict(type='str',choices=['sysDescr','sysUpTime','sysName']),asn=dict(type='str',)),snmp=dict(type='bool',),community=dict(type='str',),operation=dict(type='dict',oper_type=dict(type='str',choices=['getnext','get']))),kerberos_kdc=dict(type='dict',kerberos_cfg=dict(type='dict',tcp_only=dict(type='bool',),kpasswd_password=dict(type='str',),kadmin_server=dict(type='str',),kinit_password=dict(type='str',),kpasswd=dict(type='bool',),kinit_pricipal_name=dict(type='str',),kpasswd_server=dict(type='str',),kadmin_encrypted=dict(type='str',),kinit=dict(type='bool',),kadmin_pricipal_name=dict(type='str',),kadmin_realm=dict(type='str',),kinit_kdc=dict(type='str',),kpasswd_pricipal_name=dict(type='str',),kadmin=dict(type='bool',),kadmin_kdc=dict(type='str',),kpasswd_kdc=dict(type='str',),kadmin_password=dict(type='str',),kpasswd_encrypted=dict(type='str',),kinit_encrypted=dict(type='str',)),uuid=dict(type='str',)),imap=dict(type='dict',imap_cram_md5=dict(type='bool',),imap_port=dict(type='int',),imap_login=dict(type='bool',),imap_password=dict(type='bool',),imap_password_string=dict(type='str',),imap_username=dict(type='str',),imap_encrypted=dict(type='str',),pwd_auth=dict(type='bool',),imap_plain=dict(type='bool',),imap=dict(type='bool',),uuid=dict(type='str',))),
        name=dict(type='str',required=True,)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/health/monitor/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["monitor"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["monitor"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["monitor"][k] = v
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
    payload = build_json("monitor", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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