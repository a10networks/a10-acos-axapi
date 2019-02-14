#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_template_logging
description:
    - Logging Template
short_description: Configures A10 cgnv6.template.logging
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
    include_inside_user_mac:
        description:
        - "Include the inside user MAC address in logs"
        required: False
    facility:
        description:
        - "'kernel'= 0= Kernel; 'user'= 1= User-level; 'mail'= 2= Mail; 'daemon'= 3= System daemons; 'security-authorization'= 4= Security/authorization; 'syslog'= 5= Syslog internal; 'line-printer'= 6= Line printer; 'news'= 7= Network news; 'uucp'= 8= UUCP subsystem; 'cron'= 9= Time-related; 'security-authorization-private'= 10= Private security/authorization; 'ftp'= 11= FTP; 'ntp'= 12= NTP; 'audit'= 13= Audit; 'alert'= 14= Alert; 'clock'= 15= Clock-related; 'local0'= 16= Local use 0; 'local1'= 17= Local use 1; 'local2'= 18= Local use 2; 'local3'= 19= Local use 3; 'local4'= 20= Local use 4; 'local5'= 21= Local use 5; 'local6'= 22= Local use 6; 'local7'= 23= Local use 7; "
        required: False
    rule:
        description:
        - "Field rule"
        required: False
        suboptions:
            rule_http_requests:
                description:
                - "Field rule_http_requests"
            interim_update_interval:
                description:
                - "Log interim update of NAT mappings (Interim update interval in minutes)"
    include_partition_name:
        description:
        - "Include partition name in logging events"
        required: False
    severity:
        description:
        - "Field severity"
        required: False
        suboptions:
            severity_string:
                description:
                - "'emergency'= 0= Emergency; 'alert'= 1= Alert; 'critical'= 2= Critical; 'error'= 3= Error; 'warning'= 4= Warning; 'notice'= 5= Notice; 'informational'= 6= Informational; 'debug'= 7= Debug; "
            severity_val:
                description:
                - "Logging severity level"
    custom:
        description:
        - "Field custom"
        required: False
        suboptions:
            custom_header:
                description:
                - "'use-syslog-header'= Use syslog header as custom log header; "
            custom_message:
                description:
                - "Field custom_message"
            custom_time_stamp_format:
                description:
                - "Customize the time stamp format (Customize the time-stamp format. Default=%Y%m%d%H%M%S)"
    service_group:
        description:
        - "Set NAT logging service-group"
        required: False
    shared:
        description:
        - "Service group is in shared patition"
        required: False
    include_session_byte_count:
        description:
        - "include byte count in session deletion logs"
        required: False
    format:
        description:
        - "'binary'= Binary logging format; 'compact'= Compact ASCII logging format (Hex format with compact representation); 'custom'= Arbitrary custom logging format; 'default'= Default A10 logging format (ASCII); 'rfc5424'= RFC5424 compliant logging format; 'cef'= Common Event Format for logging; "
        required: False
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
            uuid:
                description:
                - "uuid of the object"
            ipv6:
                description:
                - "Specify source IPv6 address"
    log:
        description:
        - "Field log"
        required: False
        suboptions:
            sessions:
                description:
                - "Log all data sessions created using NAT"
            map_dhcpv6:
                description:
                - "Field map_dhcpv6"
            port_overloading:
                description:
                - "Force logging of all port-overloading sessions"
            http_requests:
                description:
                - "'host'= Log the HTTP Host Header; 'url'= Log the HTTP Request URL; "
            port_mappings:
                description:
                - "'creation'= Log only creation of NAT mappgins; 'disable'= Disable Log creation and deletion of NAT mappings; "
            merged_style:
                description:
                - "Merge creation and deletion of session logs to one"
            fixed_nat:
                description:
                - "Field fixed_nat"
    source_port:
        description:
        - "Field source_port"
        required: False
        suboptions:
            source_port_num:
                description:
                - "Set source port for sending NAT syslogs (default= 514)"
            any:
                description:
                - "Use any source port"
    uuid:
        description:
        - "uuid of the object"
        required: False
    batched_logging_disable:
        description:
        - "Disable multiple logs per packet"
        required: False
    log_receiver:
        description:
        - "Field log_receiver"
        required: False
        suboptions:
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)"
            radius:
                description:
                - "Use RADIUS server for NAT logging"
            secret_string:
                description:
                - "The RADIUS server's secret"
    name:
        description:
        - "Logging template name"
        required: True
    include_destination:
        description:
        - "Include the destination IP and port in logs"
        required: False
    include_radius_attribute:
        description:
        - "Field include_radius_attribute"
        required: False
        suboptions:
            framed_ipv6_prefix:
                description:
                - "Include radius attributes for the prefix"
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'= Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112; "
            insert_if_not_existing:
                description:
                - "Configure what string is to be inserted for custom RADIUS attributes"
            zero_in_custom_attr:
                description:
                - "Insert 0000 for standard and custom attributes in log string"
            no_quote:
                description:
                - "No quotation marks for RADIUS attributes in logs"
            attr_cfg:
                description:
                - "Field attr_cfg"
    user_tag:
        description:
        - "Customized tag"
        required: False
    disable_log_by_destination:
        description:
        - "Field disable_log_by_destination"
        required: False
        suboptions:
            udp_list:
                description:
                - "Field udp_list"
            icmp:
                description:
                - "Disable logging for icmp traffic"
            uuid:
                description:
                - "uuid of the object"
            tcp_list:
                description:
                - "Field tcp_list"
            others:
                description:
                - "Disable logging for other L4 protocols"
    rfc_custom:
        description:
        - "Field rfc_custom"
        required: False
        suboptions:
            header:
                description:
                - "Field header"
            message:
                description:
                - "Field message"
    resolution:
        description:
        - "'seconds'= Logging timestamp resolution in seconds (default); '10-milliseconds'= Logging timestamp resolution in 10s of milli-seconds; "
        required: False
    include_http:
        description:
        - "Field include_http"
        required: False
        suboptions:
            header_cfg:
                description:
                - "Field header_cfg"
            request_number:
                description:
                - "HTTP Request Number"
            file_extension:
                description:
                - "HTTP file extension"
            method:
                description:
                - "Log the HTTP Request Method"
            l4_session_info:
                description:
                - "Log the L4 session information of the HTTP request"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["batched_logging_disable","custom","disable_log_by_destination","facility","format","include_destination","include_http","include_inside_user_mac","include_partition_name","include_radius_attribute","include_session_byte_count","log","log_receiver","name","resolution","rfc_custom","rule","service_group","severity","shared","source_address","source_port","user_tag","uuid",]

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
        include_inside_user_mac=dict(type='bool',),
        facility=dict(type='str',choices=['kernel','user','mail','daemon','security-authorization','syslog','line-printer','news','uucp','cron','security-authorization-private','ftp','ntp','audit','alert','clock','local0','local1','local2','local3','local4','local5','local6','local7']),
        rule=dict(type='dict',rule_http_requests=dict(type='dict',log_every_http_request=dict(type='bool',),disable_sequence_check=dict(type='bool',),include_all_headers=dict(type='bool',),dest_port=dict(type='list',include_byte_count=dict(type='bool',),dest_port_number=dict(type='int',)),max_url_len=dict(type='int',)),interim_update_interval=dict(type='int',)),
        include_partition_name=dict(type='bool',),
        severity=dict(type='dict',severity_string=dict(type='str',choices=['emergency','alert','critical','error','warning','notice','informational','debug']),severity_val=dict(type='int',)),
        custom=dict(type='dict',custom_header=dict(type='str',choices=['use-syslog-header']),custom_message=dict(type='dict',custom_http_request_got=dict(type='str',),custom_port_batch_v2_allocated=dict(type='str',),custom_fixed_nat_allocated=dict(type='str',),custom_port_batch_v2_freed=dict(type='str',),custom_port_batch_v2_interim_update=dict(type='str',),custom_port_batch_freed=dict(type='str',),custom_fixed_nat_freed=dict(type='str',),custom_port_batch_allocated=dict(type='str',),custom_port_allocated=dict(type='str',),custom_session_deleted=dict(type='str',),custom_fixed_nat_interim_update=dict(type='str',),custom_port_freed=dict(type='str',),custom_session_created=dict(type='str',)),custom_time_stamp_format=dict(type='str',)),
        service_group=dict(type='str',),
        shared=dict(type='bool',),
        include_session_byte_count=dict(type='bool',),
        format=dict(type='str',choices=['binary','compact','custom','default','rfc5424','cef']),
        source_address=dict(type='dict',ip=dict(type='str',),uuid=dict(type='str',),ipv6=dict(type='str',)),
        log=dict(type='dict',sessions=dict(type='bool',),map_dhcpv6=dict(type='dict',map_dhcpv6_prefix_all=dict(type='bool',),map_dhcpv6_msg_type=dict(type='list',map_dhcpv6_msg_type=dict(type='str',choices=['prefix-assignment','prefix-renewal','prefix-release']))),port_overloading=dict(type='bool',),http_requests=dict(type='str',choices=['host','url']),port_mappings=dict(type='str',choices=['creation','disable']),merged_style=dict(type='bool',),fixed_nat=dict(type='dict',fixed_nat_sessions=dict(type='bool',),fixed_nat_http_requests=dict(type='str',choices=['host','url']),user_ports=dict(type='dict',user_ports=dict(type='bool',),start_time=dict(type='str',),days=dict(type='int',)),fixed_nat_port_mappings=dict(type='str',choices=['both','creation']),fixed_nat_merged_style=dict(type='bool',))),
        source_port=dict(type='dict',source_port_num=dict(type='int',),any=dict(type='bool',)),
        uuid=dict(type='str',),
        batched_logging_disable=dict(type='bool',),
        log_receiver=dict(type='dict',encrypted=dict(type='str',),radius=dict(type='bool',),secret_string=dict(type='str',)),
        name=dict(type='str',required=True,),
        include_destination=dict(type='bool',),
        include_radius_attribute=dict(type='dict',framed_ipv6_prefix=dict(type='bool',),prefix_length=dict(type='str',choices=['32','48','64','80','96','112']),insert_if_not_existing=dict(type='bool',),zero_in_custom_attr=dict(type='bool',),no_quote=dict(type='bool',),attr_cfg=dict(type='list',attr_event=dict(type='str',choices=['http-requests','port-mappings','sessions']),attr=dict(type='str',choices=['imei','imsi','msisdn','custom1','custom2','custom3']))),
        user_tag=dict(type='str',),
        disable_log_by_destination=dict(type='dict',udp_list=dict(type='list',udp_port_start=dict(type='int',),udp_port_end=dict(type='int',)),icmp=dict(type='bool',),uuid=dict(type='str',),tcp_list=dict(type='list',tcp_port_start=dict(type='int',),tcp_port_end=dict(type='int',)),others=dict(type='bool',)),
        rfc_custom=dict(type='dict',header=dict(type='dict',use_alternate_timestamp=dict(type='bool',)),message=dict(type='dict',session_created=dict(type='str',),http_request_got=dict(type='str',),session_deleted=dict(type='str',),ipv6_tech=dict(type='list',fixed_nat_freed=dict(type='str',),port_batch_freed=dict(type='str',),tech_type=dict(type='str',choices=['lsn','nat64','ds-lite','sixrd-nat64']),fixed_nat_allocated=dict(type='str',),port_allocated=dict(type='str',),port_batch_v2_allocated=dict(type='str',),port_freed=dict(type='str',),port_batch_v2_freed=dict(type='str',),port_batch_allocated=dict(type='str',)))),
        resolution=dict(type='str',choices=['seconds','10-milliseconds']),
        include_http=dict(type='dict',header_cfg=dict(type='list',custom_max_length=dict(type='int',),http_header=dict(type='str',choices=['cookie','referer','user-agent','header1','header2','header3']),max_length=dict(type='int',),custom_header_name=dict(type='str',)),request_number=dict(type='bool',),file_extension=dict(type='bool',),method=dict(type='bool',),l4_session_info=dict(type='bool',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/template/logging/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/template/logging/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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
    payload = build_json("logging", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
    payload = build_json("logging", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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