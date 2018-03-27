#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_virtual-server_port
description:
    - Virtual Port
author: A10 Networks 2018 
version_added: 1.8

options:
    
    port-number:
        description:
            - Port
    
    protocol:
        description:
            - 'tcp': TCP LB service; 'udp': UDP Port; 'others': for no tcp/udp protocol, do IP load balancing; 'diameter': diameter port; 'dns-tcp': DNS service over TCP; 'dns-udp': DNS service over UDP; 'fast-http': Fast HTTP Port; 'fix': FIX Port; 'ftp': File Transfer Protocol Port; 'ftp-proxy': ftp proxy port; 'http': HTTP Port; 'https': HTTPS port; 'http2': HTTP2 Port; 'http2s': HTTP2 SSL port; 'imap': imap proxy port; 'mlb': Message based load balancing; 'mms': Microsoft Multimedia Service Port; 'mysql': mssql port; 'mssql': mssql; 'pop3': pop3 proxy port; 'radius': RADIUS Port; 'rtsp': Real Time Streaming Protocol Port; 'sip': Session initiation protocol over UDP; 'sip-tcp': Session initiation protocol over TCP; 'sips': Session initiation protocol over TLS; 'smpp-tcp': SMPP service over TCP; 'spdy': spdy port; 'spdys': spdys port; 'smtp': SMTP Port; 'ssl-proxy': Generic SSL proxy; 'ssli': SSL insight; 'tcp-proxy': Generic TCP proxy; 'tftp': TFTP Port; 'fast-fix': Fast FIX port; choices:['tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'http2', 'http2s', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'ssl-proxy', 'ssli', 'tcp-proxy', 'tftp', 'fast-fix']
    
    range:
        description:
            - Virtual Port range (Virtual Port range value)
    
    alternate-port:
        description:
            - Alternate Virtual Port
    
    name:
        description:
            - SLB Virtual Service Name
    
    conn-limit:
        description:
            - Connection Limit
    
    reset:
        description:
            - Send client reset when connection number over limit
    
    no-logging:
        description:
            - Do not log connection over limit event
    
    use-alternate-port:
        description:
            - Use alternate virtual port
    
    alternate-port-number:
        description:
            - Virtual Port
    
    alt-protocol1:
        description:
            - 'http': HTTP Port; choices:['http']
    
    serv-sel-fail:
        description:
            - Use alternate virtual port when server selection failure
    
    when-down:
        description:
            - Use alternate virtual port when down
    
    alt-protocol2:
        description:
            - 'tcp': TCP LB service; choices:['tcp']
    
    req-fail:
        description:
            - Use alternate virtual port when L7 request fail
    
    when-down-protocol2:
        description:
            - Use alternate virtual port when down
    
    action:
        description:
            - 'enable': Enable; 'disable': Disable; choices:['enable', 'disable']
    
    def-selection-if-pref-failed:
        description:
            - 'def-selection-if-pref-failed': Use default server selection method if prefer method failed; 'def-selection-if-pref-failed-disable': Stop using default server selection method if prefer method failed; choices:['def-selection-if-pref-failed', 'def-selection-if-pref-failed-disable']
    
    ha-conn-mirror:
        description:
            - Enable for HA Conn sync
    
    on-syn:
        description:
            - Enable for HA Conn sync for l4 tcp sessions on SYN
    
    skip-rev-hash:
        description:
            - Skip rev tuple hash insertion
    
    message-switching:
        description:
            - Message switching
    
    force-routing-mode:
        description:
            - Force routing mode
    
    rate:
        description:
            - Specify the log message rate
    
    secs:
        description:
            - Specify the interval in seconds
    
    reset-on-server-selection-fail:
        description:
            - Send client reset when server selection fails
    
    clientip-sticky-nat:
        description:
            - Prefer to use same source NAT address for a client
    
    extended-stats:
        description:
            - Enable extended statistics on virtual port
    
    gslb-enable:
        description:
            - Enable Global Server Load Balancing
    
    view:
        description:
            - Specify a GSLB View (ID)
    
    snat-on-vip:
        description:
            - Enable source NAT traffic against VIP
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for virtual port; 'stats-data-disable': Disable statistical data collection for virtual port; choices:['stats-data-enable', 'stats-data-disable']
    
    syn-cookie:
        description:
            - Enable syn-cookie
    
    expand:
        description:
            - expand syn-cookie with timestamp and wscale
    
    acl-id-list:
        
    
    acl-name-list:
        
    
    aflex-scripts:
        
    
    no-auto-up-on-aflex:
        description:
            - Don't automatically mark vport up when aFleX is bound
    
    scaleout-bucket-count:
        description:
            - Number of traffic buckets
    
    scaleout-device-group:
        description:
            - Device group id
    
    pool:
        description:
            - Specify NAT pool or pool group
    
    auto:
        description:
            - Configure auto NAT for the vport
    
    precedence:
        description:
            - Set auto NAT pool as higher precedence for source NAT
    
    use-cgnv6:
        description:
            - Follow CGNv6 source NAT configuration
    
    enable-playerid-check:
        description:
            - Enable playerid checks on UDP packets once the AX is in active mode
    
    service-group:
        description:
            - Bind a Service Group to this Virtual Server (Service Group Name)
    
    ipinip:
        description:
            - Enable IP in IP
    
    rtp-sip-call-id-match:
        description:
            - rtp traffic try to match the real server of sip smp call-id session
    
    use-rcv-hop-for-resp:
        description:
            - Use receive hop for response to client(For packets on default-vlan, also config "vlan-global enable-def-vlan-l2-forwarding".)
    
    persist-type:
        description:
            - 'src-dst-ip-swap-persist': Create persist session after source IP and destination IP swap; 'use-src-ip-for-dst-persist': Use the source IP to create a destination persist session; 'use-dst-ip-for-src-persist': Use the destination IP to create source IP persist session; choices:['src-dst-ip-swap-persist', 'use-src-ip-for-dst-persist', 'use-dst-ip-for-src-persist']
    
    eth-fwd:
        description:
            - Ethernet interface number
    
    trunk-fwd:
        description:
            - Trunk interface number
    
    eth-rev:
        description:
            - Ethernet interface number
    
    trunk-rev:
        description:
            - Trunk interface number
    
    template-sip:
        description:
            - SIP template
    
    template-smpp:
        description:
            - SMPP template
    
    template-dblb:
        description:
            - DBLB Template (DBLB template name)
    
    template-connection-reuse:
        description:
            - Connection Reuse Template (Connection Reuse Template Name)
    
    template-dns:
        description:
            - DNS template (DNS template name)
    
    template-policy:
        description:
            - Policy Template (Policy template name)
    
    template-dynamic-service:
        description:
            - Dynamic Service Template (dynamic-service template name)
    
    template-persist-source-ip:
        description:
            - Source IP persistence (Source IP persistence template name)
    
    template-persist-destination-ip:
        description:
            - Destination IP persistence (Destination IP persistence template name)
    
    template-persist-ssl-sid:
        description:
            - SSL session ID persistence (Source IP Persistence Config name)
    
    template-persist-cookie:
        description:
            - Cookie persistence (Cookie persistence template name)
    
    template-imap-pop3:
        description:
            - IMAP/POP3 Template (IMAP/POP3 Config Name)
    
    template-smtp:
        description:
            - SMTP Template (SMTP Config Name)
    
    template-http:
        description:
            - HTTP Template (HTTP Config Name)
    
    template-http-policy:
        description:
            - http-policy template (http-policy template name)
    
    redirect-to-https:
        description:
            - Redirect HTTP to HTTPS
    
    template-external-service:
        description:
            - External service template (external-service template name)
    
    template-reqmod-icap:
        description:
            - ICAP reqmod template (reqmod-icap template name)
    
    template-respmod-icap:
        description:
            - ICAP respmod service template (respmod-icap template name)
    
    template-file-inspection:
        description:
            - File Inspection service template (file-inspection template name)
    
    template-server-ssl:
        description:
            - Server Side SSL Template (Server SSL Name)
    
    template-client-ssl:
        description:
            - Client SSL Template (Client SSL Config Name)
    
    template-udp:
        description:
            - L4 UDP Template (UDP Config Name)
    
    template-tcp:
        description:
            - L4 TCP Template (TCP Config Name)
    
    template-virtual-port:
        description:
            - Virtual port template (Virtual port template name)
    
    template-ftp:
        description:
            - FTP port template (Ftp template name)
    
    template-diameter:
        description:
            - Diameter Template (diameter template name)
    
    template-cache:
        description:
            - RAM caching template (Cache Template Name)
    
    template-fix:
        description:
            - FIX template (FIX Template Name)
    
    waf-template:
        description:
            - WAF template (WAF Template Name)
    
    template-ssli:
        description:
            - SSLi template (SSLi Template Name)
    
    template-tcp-proxy-client:
        description:
            - TCP Proxy Config Client (TCP Proxy Config name)
    
    template-tcp-proxy-server:
        description:
            - TCP Proxy Config Server (TCP Proxy Config name)
    
    template-tcp-proxy:
        description:
            - TCP Proxy Template Name
    
    use-default-if-no-server:
        description:
            - Use default forwarding if server selection failed
    
    template-scaleout:
        description:
            - Scaleout template (Scaleout template name)
    
    no-dest-nat:
        description:
            - Disable destination NAT, this option only supports in wildcard VIP or when a connection is operated in SSLi + EP mode
    
    port-translation:
        description:
            - Enable port translation under no-dest-nat
    
    l7-hardware-assist:
        description:
            - FPGA assist L7 packet parsing
    
    auth-cfg:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["acl_id_list","acl_name_list","action","aflex_scripts","alt_protocol1","alt_protocol2","alternate_port","alternate_port_number","auth_cfg","auto","clientip_sticky_nat","conn_limit","def_selection_if_pref_failed","enable_playerid_check","eth_fwd","eth_rev","expand","extended_stats","force_routing_mode","gslb_enable","ha_conn_mirror","ipinip","l7_hardware_assist","message_switching","name","no_auto_up_on_aflex","no_dest_nat","no_logging","on_syn","persist_type","pool","port_number","port_translation","precedence","protocol","range","rate","redirect_to_https","req_fail","reset","reset_on_server_selection_fail","rtp_sip_call_id_match","sampling_enable","scaleout_bucket_count","scaleout_device_group","secs","serv_sel_fail","service_group","skip_rev_hash","snat_on_vip","stats_data_action","syn_cookie","template_cache","template_client_ssl","template_connection_reuse","template_dblb","template_diameter","template_dns","template_dynamic_service","template_external_service","template_file_inspection","template_fix","template_ftp","template_http","template_http_policy","template_imap_pop3","template_persist_cookie","template_persist_destination_ip","template_persist_source_ip","template_persist_ssl_sid","template_policy","template_reqmod_icap","template_respmod_icap","template_scaleout","template_server_ssl","template_sip","template_smpp","template_smtp","template_ssli","template_tcp","template_tcp_proxy","template_tcp_proxy_client","template_tcp_proxy_server","template_udp","template_virtual_port","trunk_fwd","trunk_rev","use_alternate_port","use_cgnv6","use_default_if_no_server","use_rcv_hop_for_resp","user_tag","uuid","view","waf_template","when_down","when_down_protocol2",]

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        acl_id_list=dict(
            type='list' 
        ),
        acl_name_list=dict(
            type='list' 
        ),
        action=dict(
            type='str' , choices=['enable', 'disable']
        ),
        aflex_scripts=dict(
            type='list' 
        ),
        alt_protocol1=dict(
            type='str' , choices=['http']
        ),
        alt_protocol2=dict(
            type='str' , choices=['tcp']
        ),
        alternate_port=dict(
            type='bool' 
        ),
        alternate_port_number=dict(
            type='int' 
        ),
        auth_cfg=dict(
            type='str' 
        ),
        auto=dict(
            type='bool' 
        ),
        clientip_sticky_nat=dict(
            type='bool' 
        ),
        conn_limit=dict(
            type='int' 
        ),
        def_selection_if_pref_failed=dict(
            type='str' , choices=['def-selection-if-pref-failed', 'def-selection-if-pref-failed-disable']
        ),
        enable_playerid_check=dict(
            type='bool' 
        ),
        eth_fwd=dict(
            type='str' 
        ),
        eth_rev=dict(
            type='str' 
        ),
        expand=dict(
            type='bool' 
        ),
        extended_stats=dict(
            type='bool' 
        ),
        force_routing_mode=dict(
            type='bool' 
        ),
        gslb_enable=dict(
            type='bool' 
        ),
        ha_conn_mirror=dict(
            type='bool' 
        ),
        ipinip=dict(
            type='bool' 
        ),
        l7_hardware_assist=dict(
            type='bool' 
        ),
        message_switching=dict(
            type='bool' 
        ),
        name=dict(
            type='str' 
        ),
        no_auto_up_on_aflex=dict(
            type='bool' 
        ),
        no_dest_nat=dict(
            type='bool' 
        ),
        no_logging=dict(
            type='bool' 
        ),
        on_syn=dict(
            type='bool' 
        ),
        persist_type=dict(
            type='str' , choices=['src-dst-ip-swap-persist', 'use-src-ip-for-dst-persist', 'use-dst-ip-for-src-persist']
        ),
        pool=dict(
            type='str' 
        ),
        port_number=dict(
            type='int' , required=True
        ),
        port_translation=dict(
            type='bool' 
        ),
        precedence=dict(
            type='bool' 
        ),
        protocol=dict(
            type='str' , required=True, choices=['tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'http2', 'http2s', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'ssl-proxy', 'ssli', 'tcp-proxy', 'tftp', 'fast-fix']
        ),
        range=dict(
            type='int' 
        ),
        rate=dict(
            type='int' 
        ),
        redirect_to_https=dict(
            type='bool' 
        ),
        req_fail=dict(
            type='bool' 
        ),
        reset=dict(
            type='bool' 
        ),
        reset_on_server_selection_fail=dict(
            type='bool' 
        ),
        rtp_sip_call_id_match=dict(
            type='bool' 
        ),
        sampling_enable=dict(
            type='list' 
        ),
        scaleout_bucket_count=dict(
            type='int' 
        ),
        scaleout_device_group=dict(
            type='int' 
        ),
        secs=dict(
            type='int' 
        ),
        serv_sel_fail=dict(
            type='bool' 
        ),
        service_group=dict(
            type='str' 
        ),
        skip_rev_hash=dict(
            type='bool' 
        ),
        snat_on_vip=dict(
            type='bool' 
        ),
        stats_data_action=dict(
            type='str' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        syn_cookie=dict(
            type='bool' 
        ),
        template_cache=dict(
            type='str' 
        ),
        template_client_ssl=dict(
            type='str' 
        ),
        template_connection_reuse=dict(
            type='str' 
        ),
        template_dblb=dict(
            type='str' 
        ),
        template_diameter=dict(
            type='str' 
        ),
        template_dns=dict(
            type='str' 
        ),
        template_dynamic_service=dict(
            type='str' 
        ),
        template_external_service=dict(
            type='str' 
        ),
        template_file_inspection=dict(
            type='str' 
        ),
        template_fix=dict(
            type='str' 
        ),
        template_ftp=dict(
            type='str' 
        ),
        template_http=dict(
            type='str' 
        ),
        template_http_policy=dict(
            type='str' 
        ),
        template_imap_pop3=dict(
            type='str' 
        ),
        template_persist_cookie=dict(
            type='str' 
        ),
        template_persist_destination_ip=dict(
            type='str' 
        ),
        template_persist_source_ip=dict(
            type='str' 
        ),
        template_persist_ssl_sid=dict(
            type='str' 
        ),
        template_policy=dict(
            type='str' 
        ),
        template_reqmod_icap=dict(
            type='str' 
        ),
        template_respmod_icap=dict(
            type='str' 
        ),
        template_scaleout=dict(
            type='str' 
        ),
        template_server_ssl=dict(
            type='str' 
        ),
        template_sip=dict(
            type='str' 
        ),
        template_smpp=dict(
            type='str' 
        ),
        template_smtp=dict(
            type='str' 
        ),
        template_ssli=dict(
            type='str' 
        ),
        template_tcp=dict(
            type='str' 
        ),
        template_tcp_proxy=dict(
            type='str' 
        ),
        template_tcp_proxy_client=dict(
            type='str' 
        ),
        template_tcp_proxy_server=dict(
            type='str' 
        ),
        template_udp=dict(
            type='str' 
        ),
        template_virtual_port=dict(
            type='str' 
        ),
        trunk_fwd=dict(
            type='str' 
        ),
        trunk_rev=dict(
            type='str' 
        ),
        use_alternate_port=dict(
            type='bool' 
        ),
        use_cgnv6=dict(
            type='bool' 
        ),
        use_default_if_no_server=dict(
            type='bool' 
        ),
        use_rcv_hop_for_resp=dict(
            type='bool' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        view=dict(
            type='int' 
        ),
        waf_template=dict(
            type='str' 
        ),
        when_down=dict(
            type='bool' 
        ),
        when_down_protocol2=dict(
            type='bool' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    
    f_dict["port-number"] = module.params["port-number"]
    f_dict["protocol"] = module.params["protocol"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]
        # else:
        #     del module.params[x]

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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("port", module)
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

def update(module, result):
    payload = build_json("port", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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