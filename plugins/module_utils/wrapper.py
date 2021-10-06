#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex


def oper_url(partial_url):
    """Return the URL for operational data of an existing resource"""
    return partial_url + "/oper"


def stats_url(partial_url):
    """Return the URL for statistical data of and existing resource"""
    return partial_url + "/stats"


def list_url(partial_url):
    """Return the URL for a list of resources"""
    return partial_url[0:partial_url.rfind('/')]


def get(axapi_client, url, params={}):
    resp = None
    try:
        resp, status_code = axapi_client.get(url, params=params)
    except a10_ex.NotFound:
        resp, status_code = "NotFound", 400 

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
        "status_code": status_code
    }
    return call_result


def get_file(axapi_client, object_name, oper_url, filename):
    call_result = get(axapi_client, oper_url)
    file_info = call_result["response_body"]
    file_exists = False
    if file_info:
        file_list = file_info[object_name]["oper"].get("file-list", [])
        for file_obj in file_list:
            if file_obj['file'] == filename:
                call_result["response_body"] = {
                    object_name: {
                        "file": filename,
                        "file-handle": filename
                    }
                }
                file_exists = True
                break
    return call_result, file_exists


def get_list(axapi_client, existing_url):
    return get(axapi_client, list_url(existing_url))


def get_oper(axapi_client, existing_url, params={}):
    query_params = {}
    if params.get("oper"):
        for k, v in params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return get(axapi_client, oper_url(existing_url), params=query_params)


def get_stats(axapi_client, existing_url, params={}):
    query_params = {}
    if params.get("stats"):
        for k, v in params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return get(axapi_client, stats_url(existing_url), params=query_params)


def post(axapi_client, url, params={}):
    resp, status_code = axapi_client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
        "status_code": status_code
    }
    return call_result


def post_file(axapi_client, url, params={}, file_content=None, file_name=None):
    file_payload = {
        'file_content': file_content,
        'file_name': file_name
    }
    resp, status_code = axapi_client.post(url, params=params,
                                          file_content=file_content,
                                          file_name=file_name)
    params.update(file_payload)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
        "status_code": status_code
    }
    return call_result


def delete(axapi_client, url):
    resp, status_code = axapi_client.delete(url)
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": resp,
        "status_code": status_code 
    }
    return call_result


def switch_device_context(axapi_client, device_id):
    resp, status_code = axapi_client.switch_device_context(device_id)
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {"device-id": device_id},
        "response_body": resp,
        "status_code": status_code 
    }
    return call_result


def active_partition(axapi_client, a10_partition):
    resp, status_code = axapi_client.activate_partition(a10_partition)
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {"curr_part_name": a10_partition},
        "response_body": resp,
        "status_code": status_code 
    }
    return call_result
