#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_netflow_template
description:
    - IPFIX Custom Template
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "IPFIX CUSTOM Template Name"
        type: str
        required: True
    information_element_blk:
        description:
        - "Field information_element_blk"
        type: list
        required: False
        suboptions:
            information_element:
                description:
                - "'fwd-tuple-vnp-id'= Session forward tuple partition id (ID= 33028); 'rev-tuple-
          vnp-id'= Session reverse tuple partition id (ID= 33029); 'source-ipv4-address'=
          IPv4 source address in the IP packet header (ID= 8); 'source-ipv4-prefix-len'=
          Prefix length for IPv4 source address(ID= 9); 'dest-ipv4-address'= IPv4
          destination address in the IP packet header (ID= 12); 'dest-ipv4-prefix-len'=
          Prefix length for IPv4 dest address(ID= 13); 'source-ipv6-address'= IPv6 source
          address in the IP packet header (ID= 27); 'source-ipv6-prefix-len'= Prefix
          length for IPv6 source address(ID=29); 'dest-ipv6-address'= IPv6 destination
          address in the IP packet header (ID=28); 'dest-ipv6-prefix-len'= Prefix length
          for IPv6 dest address (ID=30); 'post-nat-source-ipv4-address'= IPv4 natted
          source address (ID= 225); 'post-nat-dest-ipv4-address'= IPv4 natted destination
          address(ID= 226); 'post-nat-source-ipv6-address'= IPv6 natted source address
          (ID= 281); 'post-nat-dest-ipv6-address'= IPv6 natted destination address (ID=
          282); 'source-port'= Source port identifier in the transport header (ID= 7);
          'dest-port'= Destination port identifier in the transport header (ID= 11);
          'post-nat-source-port'= L4 natted source port(ID= 227); 'post-nat-dest-port'=
          L4 natted destination port (ID= 228); 'fwd-tuple-type'= Session forward tuple
          type (ID= 33024); 'rev-tuple-type'= Session reverse tuple type (ID= 33025);
          'ip-proto'= Value of the protocol number in the IP packet header (ID= 4);
          'flow-direction'= Flow direction= 0=inbound(To an outside
          interface)/1=outbound(To an inside interface) (ID= 61); 'tcp-control-bits'=
          Cumulative of all the TCP flags seen for this flow (ID= 6); 'fwd-bytes'=
          Incoming bytes associated with an IP Flow (ID= 1); 'fwd-packets'= Incoming
          packets associated with an IP Flow (ID= 2); 'rev-bytes'= Delta bytes in reverse
          direction of bidirectional flow record (ID= 32769); 'rev-packets'= Delta
          packets in reverse direction of bidirectional flow record (ID= 32770); 'in-
          port'= Incoming interface port (ID= 10); 'out-port'= Outcoming interface port
          (ID= 14); 'in-interface'= Incoming interface name e.g. ethernet 0 (ID= 82);
          'out-interface'= Outcoming interface name e.g. ethernet 0 (ID= 32850); 'port-
          range-start'= Port number identifying the start of a range of ports (ID= 361);
          'port-range-end'= Port number identifying the end of a range of ports (ID=
          362); 'port-range-step-size'= Step size in a port range (ID= 363); 'port-range-
          num-ports'= Number of ports in a port range (ID= 364); 'rule-name'= Rule Name
          (ID= 33034); 'rule-set-name'= Rule-Set Name (ID= 33035); 'fw-source-zone'=
          Firewall Source Zone Name (ID= 33036); 'fw-dest-zone'= Firewall Dest Zone Name
          (ID= 33037); 'application-id'= Application ID (ID= 95); 'application-name'=
          Application Name (ID= 96); 'imsi'= Subscriber Attribute IMSI (ID= 455);
          'msisdn'= Subscriber Attribute MSISDN (ID= 456); 'imei'= Subscriber Attribute
          IMEI (ID= 33030); 'radius-custom1'= Radius Attribute Custom 1 (ID= 33031);
          'radius-custom2'= Radius Attribute Custom 2(ID= 33032); 'radius-custom3'=
          Radius Attribute Custom 3 (ID=33033); 'radius-custom4'= Radius Attribute Custom
          4 (ID= 33067); 'radius-custom5'= Radius Attribute Custom 5(ID= 33068); 'radius-
          custom6'= Radius Attribute Custom 6 (ID=33069); 'flow-start-msec'= The absolute
          timestamp of the first packet of the flow (ID= 152); 'flow-duration-msec'=
          Difference in time between the first observed packet of this flow and the last
          observed packet of this flow (4 bytes) (ID= 161); 'flow-duration-msec-64'=
          Difference in time between the first observed packet of this flow and the last
          observed packet of this flow (8 bytes) (ID= 33039); 'flow-end-msec'= The
          absolute timestamp of the last packet of the flow (ID= 153); 'nat-event'=
          Indicates a NAT event (ID= 230); 'fw-event'= Indicates a FW session event(ID=
          233); 'fw-deny-reset-event'= Indicates a FW deny/reset event (ID= 33038); 'cgn-
          flow-direction'= Flow direction= 0=inbound(To an outside
          interface)/1=outbound(To an inside interface)/2=hairpin(From an inside
          interface to an inside interface) (ID= 33040); 'fw-dest-fqdn'= Firewall matched
          fqdn(ID= 33041); 'flow-end-reason'= A10 flow end reason(ID= 33042); 'gtp-deny-
          reason'= Indicates a GTP deny event (ID= 33043); 'gtp-apn'= Indicates GTP APN
          (ID= 33044); 'gtp-steid'= Indicates GTP Source TEID (ID= 33045); 'gtp-dteid'=
          Indicates GTP Destination TEID (ID= 33046); 'gtp-selection-mode'= Indicates GTP
          Selection Mode (ID= 33047); 'gtp-mcc'= Indicates the MCC of the Serving Network
          (ID= 33048); 'gtp-mnc'= Indicates the MNC of the serving network (ID= 33049);
          'gtp-rat-type'= Indicates the RAT Type received in the GTP Control packet (ID=
          33050); 'gtp-pdn-pdp-type'= Indicates the PDN/PDP Type in the GTP Control
          Packet (ID= 33051); 'gtp-uli'= Indicates the User Location Information (ID=
          33052); 'gtp-enduser-v4-addr'= Indicates the Subscriber IPv4 Address (ID=
          33053); 'gtp-enduser-v6-addr'= Indicates the Subscriber IPv6 Address (ID=
          33054); 'gtp-bearer-id-or-nsapi'= Indicates the EPS Bearer ID or NSAPI of the
          Subscriber (ID= 33055); 'gtp-qci'= Indicates the QoS Profile or Traffic Class
          of the subscriber (ID= 33056); 'gtp-info-event-ind'= Indicates a GTP Info
          event(ID= 33057); 'gtp-restarted-node-ipv4'= Restarted S5 Node IPV4 Address(ID=
          33058); 'gtp-restarted-node-ipv6'= Restarted S5 Node IPV6 Address(ID= 33059);
          'gtp-c-tunnels-removed-with-node-restart'= Indicates GTP-C tunnels removed by
          Node restart (ID= 33060); 'radius-imsi'= Subscriber Attribute IMSI (Deprecated
          Field) (ID= 455); 'radius-msisdn'= Subscriber Attribute MSISDN (Deprecated
          Field) (ID= 456); 'radius-imei'= Subscriber Attribute IMEI (Deprecated Field)
          (ID= 33030); 'event-time-msec'= The absolute time in milliseconds of an event
          observation(ID= 323); 'security-event-type'= Type of security event(ID= 33063);
          'limit-exceeded-count'= Limit exceeded count for FW concurrent session(ID=
          33062); 'rate-limit-key'= Rate Limit Key(ID= 33064); 'rate-limit-type'= Rate
          Limit Type(ID= 33065); 'rate-limit-drop-count'= Rate Limit Drop Count(ID=
          33066);"
                type: str
    ipfix_template_id:
        description:
        - "Custom IPFIX Template ID"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["information_element_blk", "ipfix_template_id", "name", "user_tag", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'name': {'type': 'str', 'required': True, },
        'information_element_blk': {'type': 'list', 'information_element': {'type': 'str', 'choices': ['fwd-tuple-vnp-id', 'rev-tuple-vnp-id', 'source-ipv4-address', 'source-ipv4-prefix-len', 'dest-ipv4-address', 'dest-ipv4-prefix-len', 'source-ipv6-address', 'source-ipv6-prefix-len', 'dest-ipv6-address', 'dest-ipv6-prefix-len', 'post-nat-source-ipv4-address', 'post-nat-dest-ipv4-address', 'post-nat-source-ipv6-address', 'post-nat-dest-ipv6-address', 'source-port', 'dest-port', 'post-nat-source-port', 'post-nat-dest-port', 'fwd-tuple-type', 'rev-tuple-type', 'ip-proto', 'flow-direction', 'tcp-control-bits', 'fwd-bytes', 'fwd-packets', 'rev-bytes', 'rev-packets', 'in-port', 'out-port', 'in-interface', 'out-interface', 'port-range-start', 'port-range-end', 'port-range-step-size', 'port-range-num-ports', 'rule-name', 'rule-set-name', 'fw-source-zone', 'fw-dest-zone', 'application-id', 'application-name', 'imsi', 'msisdn', 'imei', 'radius-custom1', 'radius-custom2', 'radius-custom3', 'radius-custom4', 'radius-custom5', 'radius-custom6', 'flow-start-msec', 'flow-duration-msec', 'flow-duration-msec-64', 'flow-end-msec', 'nat-event', 'fw-event', 'fw-deny-reset-event', 'cgn-flow-direction', 'fw-dest-fqdn', 'flow-end-reason', 'gtp-deny-reason', 'gtp-apn', 'gtp-steid', 'gtp-dteid', 'gtp-selection-mode', 'gtp-mcc', 'gtp-mnc', 'gtp-rat-type', 'gtp-pdn-pdp-type', 'gtp-uli', 'gtp-enduser-v4-addr', 'gtp-enduser-v6-addr', 'gtp-bearer-id-or-nsapi', 'gtp-qci', 'gtp-info-event-ind', 'gtp-restarted-node-ipv4', 'gtp-restarted-node-ipv6', 'gtp-c-tunnels-removed-with-node-restart', 'radius-imsi', 'radius-msisdn', 'radius-imei', 'event-time-msec', 'security-event-type', 'limit-exceeded-count', 'rate-limit-key', 'rate-limit-type', 'rate-limit-drop-count']}},
        'ipfix_template_id': {'type': 'int', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/netflow/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["template"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["template"].get(k) != v:
            change_results["changed"] = True
            config_changes["template"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("template", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)


    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["template"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["template-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

if __name__ == '__main__':
    main()
