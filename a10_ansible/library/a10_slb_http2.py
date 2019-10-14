#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_http2
description:
    - Configure http2
short_description: Configures A10 slb.http2
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'connection_preface_rcvd'= Connection preface rcvd; 'control_frame'= Control Frame Rcvd; 'headers_frame'= HEADERS Frame Rcvd; 'continuation_frame'= CONTINUATION Frame Rcvd; 'rst_frame_rcvd'= RST_STREAM Frame Rcvd; 'settings_frame'= SETTINGS Frame Rcvd; 'window_update_frame'= WINDOW_UPDATE Frame Rcvd; 'ping_frame'= PING Frame Rcvd; 'goaway_frame'= GOAWAY Frame Rcvd; 'priority_frame'= PRIORITY Frame Rcvd; 'data_frame'= DATA Frame Recvd; 'unknown_frame'= Unknown Frame Recvd; 'connection_preface_sent'= Connection preface sent; 'settings_frame_sent'= SETTINGS Frame Sent; 'settings_ack_sent'= SETTINGS ACK Frame Sent; 'empty_settings_sent'= Empty SETTINGS Frame Sent; 'ping_frame_sent'= PING Frame Sent; 'window_update_frame_sent'= WINDOW_UPDATE Frame Sent; 'rst_frame_sent'= RST_STREAM Frame Sent; 'goaway_frame_sent'= GOAWAY Frame Sent; 'header_to_app'= HEADER Frame to HTTP; 'data_to_app'= DATA Frame to HTTP; 'protocol_error'= Protocol Error; 'internal_error'= Internal Error; 'proxy_alloc_error'= HTTP2 Proxy alloc Error; 'split_buff_fail'= Splitting Buffer Failed; 'invalid_frame_size'= Invalid Frame Size Rcvd; 'error_max_invalid_stream'= Max Invalid Stream Rcvd; 'data_no_stream'= DATA Frame Rcvd on non-existent stream; 'flow_control_error'= Flow Control Error; 'settings_timeout'= Settings Timeout; 'frame_size_error'= Frame Size Error; 'refused_stream'= Refused Stream; 'cancel'= cancel; 'compression_error'= compression error; 'connect_error'= connect error; 'enhance_your_calm'= enhance your calm error; 'inadequate_security'= inadequate security; 'http_1_1_required'= HTTP1.1 Required; 'deflate_alloc_fail'= deflate alloc fail; 'inflate_alloc_fail'= inflate alloc fail; 'inflate_header_fail'= Inflate Header Fail; 'bad_connection_preface'= Bad Connection Preface; 'cant_allocate_control_frame'= Cant allocate control frame; 'cant_allocate_settings_frame'= Cant allocate SETTINGS frame; 'bad_frame_type_for_stream_state'= Bad frame type for stream state; 'wrong_stream_state'= Wrong Stream State; 'data_queue_alloc_error'= Data Queue Alloc Error; 'buff_alloc_error'= Buff alloc error; 'cant_allocate_rst_frame'= Cant allocate RST_STREAM frame; 'cant_allocate_goaway_frame'= Cant allocate GOAWAY frame; 'cant_allocate_ping_frame'= Cant allocate PING frame; 'cant_allocate_stream'= Cant allocate stream; 'cant_allocate_window_frame'= Cant allocate WINDOW_UPDATE frame; 'header_no_stream'= header no stream; 'header_padlen_gt_frame_payload'= Header padlen greater than frame payload size; 'streams_gt_max_concur_streams'= Streams greater than max allowed concurrent streams; 'idle_state_unexpected_frame'= Unxpected frame received in idle state; 'reserved_local_state_unexpected_frame'= Unexpected frame received in reserved local state; 'reserved_remote_state_unexpected_frame'= Unexpected frame received in reserved remote state; 'half_closed_remote_state_unexpected_frame'= Unexpected frame received in half closed remote state; 'closed_state_unexpected_frame'= Unexpected frame received in closed state; 'zero_window_size_on_stream'= Window Update with zero increment rcvd; 'exceeds_max_window_size_stream'= Window Update with increment that results in exceeding max window; 'stream_closed'= stream closed; 'continuation_before_headers'= CONTINUATION frame with no headers frame; 'invalid_frame_during_headers'= frame before headers were complete; 'headers_after_continuation'= headers frame before CONTINUATION was complete; 'invalid_push_promise'= unexpected PUSH_PROMISE frame; 'invalid_stream_id'= received invalid stream ID; 'headers_interleaved'= headers interleaved on streams; 'trailers_no_end_stream'= trailers not marked as end-of-stream; 'invalid_setting_value'= invalid setting-frame value; 'invalid_window_update'= window-update value out of range; 'frame_header_bytes_received'= frame header bytes received; 'frame_header_bytes_sent'= frame header bytes sent; 'control_bytes_received'= HTTP/2 control frame bytes received; 'control_bytes_sent'= HTTP/2 control frame bytes sent; 'header_bytes_received'= HTTP/2 header bytes received; 'header_bytes_sent'= HTTP/2 header bytes sent; 'data_bytes_received'= HTTP/2 data bytes received; 'data_bytes_sent'= HTTP/2 data bytes sent; 'total_bytes_received'= HTTP/2 total bytes received; 'total_bytes_sent'= HTTP/2 total bytes sent; 'peak_proxy'= Peak Proxy Conns; 'control_frame_sent'= Control Frame Sent; 'continuation_frame_sent'= CONTINUATION Frame Sent; 'data_frame_sent'= DATA Frame Sent; 'headers_frame_sent'= HEADERS Frame Sent; 'priority_frame_sent'= PRIORITY Frame Sent; 'settings_ack_rcvd'= SETTINGS ACK Frame Rcvd; 'empty_settings_rcvd'= Empty SETTINGS Frame Rcvd; 'alloc_fail_total'= Alloc Fail - Total; 'err_rcvd_total'= Error Rcvd - Total; 'err_sent_total'= Error Rent - Total; 'err_sent_proto_err'= Error Sent - PROTOCOL_ERROR; 'err_sent_internal_err'= Error Sent - INTERNAL_ERROR; 'err_sent_flow_control'= Error Sent - FLOW_CONTROL_ERROR; 'err_sent_setting_timeout'= Error Sent - SETTINGS_TIMEOUT; 'err_sent_stream_closed'= Error Sent - STREAM_CLOSED; 'err_sent_frame_size_err'= Error Sent - FRAME_SIZE_ERROR; 'err_sent_refused_stream'= Error Sent - REFUSED_STREAM; 'err_sent_cancel'= Error Sent - CANCEL; 'err_sent_compression_err'= Error Sent - COMPRESSION_ERROR; 'err_sent_connect_err'= Error Sent - CONNECT_ERROR; 'err_sent_your_calm'= Error Sent - ENHANCE_YOUR_CALM; 'err_sent_inadequate_security'= Error Sent - INADEQUATE_SECURITY; 'err_sent_http11_required'= Error Sent - HTTP_1_1_REQUIRED; "
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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_proxy','total_proxy','connection_preface_rcvd','control_frame','headers_frame','continuation_frame','rst_frame_rcvd','settings_frame','window_update_frame','ping_frame','goaway_frame','priority_frame','data_frame','unknown_frame','connection_preface_sent','settings_frame_sent','settings_ack_sent','empty_settings_sent','ping_frame_sent','window_update_frame_sent','rst_frame_sent','goaway_frame_sent','header_to_app','data_to_app','protocol_error','internal_error','proxy_alloc_error','split_buff_fail','invalid_frame_size','error_max_invalid_stream','data_no_stream','flow_control_error','settings_timeout','frame_size_error','refused_stream','cancel','compression_error','connect_error','enhance_your_calm','inadequate_security','http_1_1_required','deflate_alloc_fail','inflate_alloc_fail','inflate_header_fail','bad_connection_preface','cant_allocate_control_frame','cant_allocate_settings_frame','bad_frame_type_for_stream_state','wrong_stream_state','data_queue_alloc_error','buff_alloc_error','cant_allocate_rst_frame','cant_allocate_goaway_frame','cant_allocate_ping_frame','cant_allocate_stream','cant_allocate_window_frame','header_no_stream','header_padlen_gt_frame_payload','streams_gt_max_concur_streams','idle_state_unexpected_frame','reserved_local_state_unexpected_frame','reserved_remote_state_unexpected_frame','half_closed_remote_state_unexpected_frame','closed_state_unexpected_frame','zero_window_size_on_stream','exceeds_max_window_size_stream','stream_closed','continuation_before_headers','invalid_frame_during_headers','headers_after_continuation','invalid_push_promise','invalid_stream_id','headers_interleaved','trailers_no_end_stream','invalid_setting_value','invalid_window_update','frame_header_bytes_received','frame_header_bytes_sent','control_bytes_received','control_bytes_sent','header_bytes_received','header_bytes_sent','data_bytes_received','data_bytes_sent','total_bytes_received','total_bytes_sent','peak_proxy','control_frame_sent','continuation_frame_sent','data_frame_sent','headers_frame_sent','priority_frame_sent','settings_ack_rcvd','empty_settings_rcvd','alloc_fail_total','err_rcvd_total','err_sent_total','err_sent_proto_err','err_sent_internal_err','err_sent_flow_control','err_sent_setting_timeout','err_sent_stream_closed','err_sent_frame_size_err','err_sent_refused_stream','err_sent_cancel','err_sent_compression_err','err_sent_connect_err','err_sent_your_calm','err_sent_inadequate_security','err_sent_http11_required'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http2"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http2"

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
        for k, v in payload["http2"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["http2"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["http2"][k] = v
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
    payload = build_json("http2", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
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
        result = absent(module, result)
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