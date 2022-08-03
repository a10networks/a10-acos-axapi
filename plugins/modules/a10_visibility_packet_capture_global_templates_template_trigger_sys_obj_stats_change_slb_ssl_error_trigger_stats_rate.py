#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_slb_ssl_error_trigger_stats_rate
description:
    - Configure stats to trigger packet capture on increment rate
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    threshold_exceeded_by:
        description:
        - "Set the threshold to the number of times greater than the previous duration to
          start the capture, default is 5"
        type: int
        required: False
    duration:
        description:
        - "Time in seconds to look for the anomaly, default is 60"
        type: int
        required: False
    app_data_in_handshake:
        description:
        - "Enable automatic packet-capture for app data in handshake"
        type: bool
        required: False
    attempt_to_reuse_sess_in_diff_context:
        description:
        - "Enable automatic packet-capture for attempt to reuse sess in diff context"
        type: bool
        required: False
    bad_alert_record:
        description:
        - "Enable automatic packet-capture for bad alert record"
        type: bool
        required: False
    bad_authentication_type:
        description:
        - "Enable automatic packet-capture for bad authentication type"
        type: bool
        required: False
    bad_change_cipher_spec:
        description:
        - "Enable automatic packet-capture for bad change cipher spec"
        type: bool
        required: False
    bad_checksum:
        description:
        - "Enable automatic packet-capture for bad checksum"
        type: bool
        required: False
    bad_data_returned_by_callback:
        description:
        - "Enable automatic packet-capture for bad data returned by callback"
        type: bool
        required: False
    bad_decompression:
        description:
        - "Enable automatic packet-capture for bad decompression"
        type: bool
        required: False
    bad_dh_g_length:
        description:
        - "Enable automatic packet-capture for bad dh g length"
        type: bool
        required: False
    bad_dh_pub_key_length:
        description:
        - "Enable automatic packet-capture for bad dh pub key length"
        type: bool
        required: False
    bad_dh_p_length:
        description:
        - "Enable automatic packet-capture for bad dh p length"
        type: bool
        required: False
    bad_digest_length:
        description:
        - "Enable automatic packet-capture for bad digest length"
        type: bool
        required: False
    bad_dsa_signature:
        description:
        - "Enable automatic packet-capture for bad dsa signature"
        type: bool
        required: False
    bad_hello_request:
        description:
        - "Enable automatic packet-capture for bad hello request"
        type: bool
        required: False
    bad_length:
        description:
        - "Enable automatic packet-capture for bad length"
        type: bool
        required: False
    bad_mac_decode:
        description:
        - "Enable automatic packet-capture for bad mac decode"
        type: bool
        required: False
    bad_message_type:
        description:
        - "Enable automatic packet-capture for bad message type"
        type: bool
        required: False
    bad_packet_length:
        description:
        - "Enable automatic packet-capture for bad packet length"
        type: bool
        required: False
    bad_protocol_version_counter:
        description:
        - "Enable automatic packet-capture for bad protocol version counter"
        type: bool
        required: False
    bad_response_argument:
        description:
        - "Enable automatic packet-capture for bad response argument"
        type: bool
        required: False
    bad_rsa_decrypt:
        description:
        - "Enable automatic packet-capture for bad rsa decrypt"
        type: bool
        required: False
    bad_rsa_encrypt:
        description:
        - "Enable automatic packet-capture for bad rsa encrypt"
        type: bool
        required: False
    bad_rsa_e_length:
        description:
        - "Enable automatic packet-capture for bad rsa e length"
        type: bool
        required: False
    bad_rsa_modulus_length:
        description:
        - "Enable automatic packet-capture for bad rsa modulus length"
        type: bool
        required: False
    bad_rsa_signature:
        description:
        - "Enable automatic packet-capture for bad rsa signature"
        type: bool
        required: False
    bad_signature:
        description:
        - "Enable automatic packet-capture for bad signature"
        type: bool
        required: False
    bad_ssl_filetype:
        description:
        - "Enable automatic packet-capture for bad ssl filetype"
        type: bool
        required: False
    bad_ssl_session_id_length:
        description:
        - "Enable automatic packet-capture for bad ssl session id length"
        type: bool
        required: False
    bad_state:
        description:
        - "Enable automatic packet-capture for bad state"
        type: bool
        required: False
    bad_write_retry:
        description:
        - "Enable automatic packet-capture for bad write retry"
        type: bool
        required: False
    bio_not_set:
        description:
        - "Enable automatic packet-capture for bio not set"
        type: bool
        required: False
    block_cipher_pad_is_wrong:
        description:
        - "Enable automatic packet-capture for block cipher pad is wrong"
        type: bool
        required: False
    bn_lib:
        description:
        - "Enable automatic packet-capture for bn lib"
        type: bool
        required: False
    ca_dn_length_mismatch:
        description:
        - "Enable automatic packet-capture for ca dn length mismatch"
        type: bool
        required: False
    ca_dn_too_long:
        description:
        - "Enable automatic packet-capture for ca dn too long"
        type: bool
        required: False
    ccs_received_early:
        description:
        - "Enable automatic packet-capture for ccs received early"
        type: bool
        required: False
    certificate_verify_failed:
        description:
        - "Enable automatic packet-capture for certificate verify failed"
        type: bool
        required: False
    cert_length_mismatch:
        description:
        - "Enable automatic packet-capture for cert length mismatch"
        type: bool
        required: False
    challenge_is_different:
        description:
        - "Enable automatic packet-capture for challenge is different"
        type: bool
        required: False
    cipher_code_wrong_length:
        description:
        - "Enable automatic packet-capture for cipher code wrong length"
        type: bool
        required: False
    cipher_or_hash_unavailable:
        description:
        - "Enable automatic packet-capture for cipher or hash unavailable"
        type: bool
        required: False
    cipher_table_src_error:
        description:
        - "Enable automatic packet-capture for cipher table src error"
        type: bool
        required: False
    compressed_length_too_long:
        description:
        - "Enable automatic packet-capture for compressed length too long"
        type: bool
        required: False
    compression_failure:
        description:
        - "Enable automatic packet-capture for compression failure"
        type: bool
        required: False
    compression_library_error:
        description:
        - "Enable automatic packet-capture for compression library error"
        type: bool
        required: False
    connection_id_is_different:
        description:
        - "Enable automatic packet-capture for connection id is different"
        type: bool
        required: False
    connection_type_not_set:
        description:
        - "Enable automatic packet-capture for connection type not set"
        type: bool
        required: False
    data_between_ccs_and_finished:
        description:
        - "Enable automatic packet-capture for data between ccs and finished"
        type: bool
        required: False
    data_length_too_long:
        description:
        - "Enable automatic packet-capture for data length too long"
        type: bool
        required: False
    decryption_failed:
        description:
        - "Enable automatic packet-capture for decryption failed"
        type: bool
        required: False
    decryption_failed_or_bad_record_mac:
        description:
        - "Enable automatic packet-capture for decryption failed or bad record mac"
        type: bool
        required: False
    dh_public_value_length_is_wrong:
        description:
        - "Enable automatic packet-capture for dh public value length is wrong"
        type: bool
        required: False
    digest_check_failed:
        description:
        - "Enable automatic packet-capture for digest check failed"
        type: bool
        required: False
    encrypted_length_too_long:
        description:
        - "Enable automatic packet-capture for encrypted length too long"
        type: bool
        required: False
    error_generating_tmp_rsa_key:
        description:
        - "Enable automatic packet-capture for error generating tmp rsa key"
        type: bool
        required: False
    error_in_received_cipher_list:
        description:
        - "Enable automatic packet-capture for error in received cipher list"
        type: bool
        required: False
    excessive_message_size:
        description:
        - "Enable automatic packet-capture for excessive message size"
        type: bool
        required: False
    extra_data_in_message:
        description:
        - "Enable automatic packet-capture for extra data in message"
        type: bool
        required: False
    got_a_fin_before_a_ccs:
        description:
        - "Enable automatic packet-capture for got a fin before a ccs"
        type: bool
        required: False
    https_proxy_request:
        description:
        - "Enable automatic packet-capture for https proxy request"
        type: bool
        required: False
    http_request:
        description:
        - "Enable automatic packet-capture for http request"
        type: bool
        required: False
    illegal_padding:
        description:
        - "Enable automatic packet-capture for illegal padding"
        type: bool
        required: False
    inappropriate_fallback:
        description:
        - "Enable automatic packet-capture for inappropriate fallback"
        type: bool
        required: False
    invalid_challenge_length:
        description:
        - "Enable automatic packet-capture for invalid challenge length"
        type: bool
        required: False
    invalid_command:
        description:
        - "Enable automatic packet-capture for invalid command"
        type: bool
        required: False
    invalid_purpose:
        description:
        - "Enable automatic packet-capture for invalid purpose"
        type: bool
        required: False
    invalid_status_response:
        description:
        - "Enable automatic packet-capture for invalid status response"
        type: bool
        required: False
    invalid_trust:
        description:
        - "Enable automatic packet-capture for invalid trust"
        type: bool
        required: False
    key_arg_too_long:
        description:
        - "Enable automatic packet-capture for key arg too long"
        type: bool
        required: False
    krb5:
        description:
        - "Enable automatic packet-capture for krb5"
        type: bool
        required: False
    krb5_client_cc_principal:
        description:
        - "Enable automatic packet-capture for krb5 client cc principal"
        type: bool
        required: False
    krb5_client_get_cred:
        description:
        - "Enable automatic packet-capture for krb5 client get cred"
        type: bool
        required: False
    krb5_client_init:
        description:
        - "Enable automatic packet-capture for krb5 client init"
        type: bool
        required: False
    krb5_client_mk_req:
        description:
        - "Enable automatic packet-capture for krb5 client mk_req"
        type: bool
        required: False
    krb5_server_bad_ticket:
        description:
        - "Enable automatic packet-capture for krb5 server bad ticket"
        type: bool
        required: False
    krb5_server_init:
        description:
        - "Enable automatic packet-capture for krb5 server init"
        type: bool
        required: False
    krb5_server_rd_req:
        description:
        - "Enable automatic packet-capture for krb5 server rd_req"
        type: bool
        required: False
    krb5_server_tkt_expired:
        description:
        - "Enable automatic packet-capture for krb5 server tkt expired"
        type: bool
        required: False
    krb5_server_tkt_not_yet_valid:
        description:
        - "Enable automatic packet-capture for krb5 server tkt not yet valid"
        type: bool
        required: False
    krb5_server_tkt_skew:
        description:
        - "Enable automatic packet-capture for krb5 server tkt skew"
        type: bool
        required: False
    length_mismatch:
        description:
        - "Enable automatic packet-capture for length mismatch"
        type: bool
        required: False
    length_too_short:
        description:
        - "Enable automatic packet-capture for length too short"
        type: bool
        required: False
    library_bug:
        description:
        - "Enable automatic packet-capture for library bug"
        type: bool
        required: False
    library_has_no_ciphers:
        description:
        - "Enable automatic packet-capture for library has no ciphers"
        type: bool
        required: False
    mast_key_too_long:
        description:
        - "Enable automatic packet-capture for mast key too long"
        type: bool
        required: False
    message_too_long:
        description:
        - "Enable automatic packet-capture for message too long"
        type: bool
        required: False
    missing_dh_dsa_cert:
        description:
        - "Enable automatic packet-capture for missing dh dsa cert"
        type: bool
        required: False
    missing_dh_key:
        description:
        - "Enable automatic packet-capture for missing dh key"
        type: bool
        required: False
    missing_dh_rsa_cert:
        description:
        - "Enable automatic packet-capture for missing dh rsa cert"
        type: bool
        required: False
    missing_dsa_signing_cert:
        description:
        - "Enable automatic packet-capture for missing dsa signing cert"
        type: bool
        required: False
    missing_export_tmp_dh_key:
        description:
        - "Enable automatic packet-capture for missing export tmp dh key"
        type: bool
        required: False
    missing_export_tmp_rsa_key:
        description:
        - "Enable automatic packet-capture for missing export tmp rsa key"
        type: bool
        required: False
    missing_rsa_certificate:
        description:
        - "Enable automatic packet-capture for missing rsa certificate"
        type: bool
        required: False
    missing_rsa_encrypting_cert:
        description:
        - "Enable automatic packet-capture for missing rsa encrypting cert"
        type: bool
        required: False
    missing_rsa_signing_cert:
        description:
        - "Enable automatic packet-capture for missing rsa signing cert"
        type: bool
        required: False
    missing_tmp_dh_key:
        description:
        - "Enable automatic packet-capture for missing tmp dh key"
        type: bool
        required: False
    missing_tmp_rsa_key:
        description:
        - "Enable automatic packet-capture for missing tmp rsa key"
        type: bool
        required: False
    missing_tmp_rsa_pkey:
        description:
        - "Enable automatic packet-capture for missing tmp rsa pkey"
        type: bool
        required: False
    missing_verify_message:
        description:
        - "Enable automatic packet-capture for missing verify message"
        type: bool
        required: False
    non_sslv2_initial_packet:
        description:
        - "Enable automatic packet-capture for non sslv2 initial packet"
        type: bool
        required: False
    no_certificates_returned:
        description:
        - "Enable automatic packet-capture for no certificates returned"
        type: bool
        required: False
    no_certificate_assigned:
        description:
        - "Enable automatic packet-capture for no certificate assigned"
        type: bool
        required: False
    no_certificate_returned:
        description:
        - "Enable automatic packet-capture for no certificate returned"
        type: bool
        required: False
    no_certificate_set:
        description:
        - "Enable automatic packet-capture for no certificate set"
        type: bool
        required: False
    no_certificate_specified:
        description:
        - "Enable automatic packet-capture for no certificate specified"
        type: bool
        required: False
    no_ciphers_available:
        description:
        - "Enable automatic packet-capture for no ciphers available"
        type: bool
        required: False
    no_ciphers_passed:
        description:
        - "Enable automatic packet-capture for no ciphers passed"
        type: bool
        required: False
    no_ciphers_specified:
        description:
        - "Enable automatic packet-capture for no ciphers specified"
        type: bool
        required: False
    no_cipher_list:
        description:
        - "Enable automatic packet-capture for no cipher list"
        type: bool
        required: False
    no_cipher_match:
        description:
        - "Enable automatic packet-capture for no cipher match"
        type: bool
        required: False
    no_client_cert_received:
        description:
        - "Enable automatic packet-capture for no client cert received"
        type: bool
        required: False
    no_compression_specified:
        description:
        - "Enable automatic packet-capture for no compression specified"
        type: bool
        required: False
    no_method_specified:
        description:
        - "Enable automatic packet-capture for no method specified"
        type: bool
        required: False
    no_privatekey:
        description:
        - "Enable automatic packet-capture for no privatekey"
        type: bool
        required: False
    no_private_key_assigned:
        description:
        - "Enable automatic packet-capture for no private key assigned"
        type: bool
        required: False
    no_protocols_available:
        description:
        - "Enable automatic packet-capture for no protocols available"
        type: bool
        required: False
    no_publickey:
        description:
        - "Enable automatic packet-capture for no publickey"
        type: bool
        required: False
    no_shared_cipher:
        description:
        - "Enable automatic packet-capture for no shared cipher"
        type: bool
        required: False
    no_verify_callback:
        description:
        - "Enable automatic packet-capture for no verify callback"
        type: bool
        required: False
    null_ssl_ctx:
        description:
        - "Enable automatic packet-capture for null ssl ctx"
        type: bool
        required: False
    null_ssl_method_passed:
        description:
        - "Enable automatic packet-capture for null ssl method passed"
        type: bool
        required: False
    old_session_cipher_not_returned:
        description:
        - "Enable automatic packet-capture for old session cipher not returned"
        type: bool
        required: False
    packet_length_too_long:
        description:
        - "Enable automatic packet-capture for packet length too long"
        type: bool
        required: False
    path_too_long:
        description:
        - "Enable automatic packet-capture for path too long"
        type: bool
        required: False
    peer_did_not_return_a_certificate:
        description:
        - "Enable automatic packet-capture for peer did not return a certificate"
        type: bool
        required: False
    peer_error:
        description:
        - "Enable automatic packet-capture for peer error"
        type: bool
        required: False
    peer_error_certificate:
        description:
        - "Enable automatic packet-capture for peer error certificate"
        type: bool
        required: False
    peer_error_no_certificate:
        description:
        - "Enable automatic packet-capture for peer error no certificate"
        type: bool
        required: False
    peer_error_no_cipher:
        description:
        - "Enable automatic packet-capture for peer error no cipher"
        type: bool
        required: False
    peer_error_unsupported_certificate_type:
        description:
        - "Enable automatic packet-capture for peer error unsupported certificate type"
        type: bool
        required: False
    pre_mac_length_too_long:
        description:
        - "Enable automatic packet-capture for pre mac length too long"
        type: bool
        required: False
    problems_mapping_cipher_functions:
        description:
        - "Enable automatic packet-capture for problems mapping cipher functions"
        type: bool
        required: False
    protocol_is_shutdown:
        description:
        - "Enable automatic packet-capture for protocol is shutdown"
        type: bool
        required: False
    public_key_encrypt_error:
        description:
        - "Enable automatic packet-capture for public key encrypt error"
        type: bool
        required: False
    public_key_is_not_rsa:
        description:
        - "Enable automatic packet-capture for public key is not rsa"
        type: bool
        required: False
    public_key_not_rsa:
        description:
        - "Enable automatic packet-capture for public key not rsa"
        type: bool
        required: False
    read_bio_not_set:
        description:
        - "Enable automatic packet-capture for read bio not set"
        type: bool
        required: False
    read_wrong_packet_type:
        description:
        - "Enable automatic packet-capture for read wrong packet type"
        type: bool
        required: False
    record_length_mismatch:
        description:
        - "Enable automatic packet-capture for record length mismatch"
        type: bool
        required: False
    record_too_large:
        description:
        - "Enable automatic packet-capture for record too large"
        type: bool
        required: False
    record_too_small:
        description:
        - "Enable automatic packet-capture for record too small"
        type: bool
        required: False
    required_cipher_missing:
        description:
        - "Enable automatic packet-capture for required cipher missing"
        type: bool
        required: False
    reuse_cert_length_not_zero:
        description:
        - "Enable automatic packet-capture for reuse cert length not zero"
        type: bool
        required: False
    reuse_cert_type_not_zero:
        description:
        - "Enable automatic packet-capture for reuse cert type not zero"
        type: bool
        required: False
    reuse_cipher_list_not_zero:
        description:
        - "Enable automatic packet-capture for reuse cipher list not zero"
        type: bool
        required: False
    scsv_received_when_renegotiating:
        description:
        - "Enable automatic packet-capture for scsv received when renegotiating"
        type: bool
        required: False
    session_id_context_uninitialized:
        description:
        - "Enable automatic packet-capture for session id context uninitialized"
        type: bool
        required: False
    short_read:
        description:
        - "Enable automatic packet-capture for short read"
        type: bool
        required: False
    signature_for_non_signing_certificate:
        description:
        - "Enable automatic packet-capture for signature for non signing certificate"
        type: bool
        required: False
    ssl23_doing_session_id_reuse:
        description:
        - "Enable automatic packet-capture for ssl23 doing session id reuse"
        type: bool
        required: False
    ssl2_connection_id_too_long:
        description:
        - "Enable automatic packet-capture for ssl2 connection id too long"
        type: bool
        required: False
    ssl3_session_id_too_long:
        description:
        - "Enable automatic packet-capture for ssl3 session id too long"
        type: bool
        required: False
    ssl3_session_id_too_short:
        description:
        - "Enable automatic packet-capture for ssl3 session id too short"
        type: bool
        required: False
    sslv3_alert_bad_certificate:
        description:
        - "Enable automatic packet-capture for sslv3 alert bad certificate"
        type: bool
        required: False
    sslv3_alert_bad_record_mac:
        description:
        - "Enable automatic packet-capture for sslv3 alert bad record mac"
        type: bool
        required: False
    sslv3_alert_certificate_expired:
        description:
        - "Enable automatic packet-capture for sslv3 alert certificate expired"
        type: bool
        required: False
    sslv3_alert_certificate_revoked:
        description:
        - "Enable automatic packet-capture for sslv3 alert certificate revoked"
        type: bool
        required: False
    sslv3_alert_certificate_unknown:
        description:
        - "Enable automatic packet-capture for sslv3 alert certificate unknown"
        type: bool
        required: False
    sslv3_alert_decompression_failure:
        description:
        - "Enable automatic packet-capture for sslv3 alert decompression failure"
        type: bool
        required: False
    sslv3_alert_handshake_failure:
        description:
        - "Enable automatic packet-capture for sslv3 alert handshake failure"
        type: bool
        required: False
    sslv3_alert_illegal_parameter:
        description:
        - "Enable automatic packet-capture for sslv3 alert illegal parameter"
        type: bool
        required: False
    sslv3_alert_no_certificate:
        description:
        - "Enable automatic packet-capture for sslv3 alert no certificate"
        type: bool
        required: False
    sslv3_alert_peer_error_cert:
        description:
        - "Enable automatic packet-capture for sslv3 alert peer error cert"
        type: bool
        required: False
    sslv3_alert_peer_error_no_cert:
        description:
        - "Enable automatic packet-capture for sslv3 alert peer error no cert"
        type: bool
        required: False
    sslv3_alert_peer_error_no_cipher:
        description:
        - "Enable automatic packet-capture for sslv3 alert peer error no cipher"
        type: bool
        required: False
    sslv3_alert_peer_error_unsupp_cert_type:
        description:
        - "Enable automatic packet-capture for sslv3 alert peer error unsupp cert type"
        type: bool
        required: False
    sslv3_alert_unexpected_msg:
        description:
        - "Enable automatic packet-capture for sslv3 alert unexpected msg"
        type: bool
        required: False
    sslv3_alert_unknown_remote_err_type:
        description:
        - "Enable automatic packet-capture for sslv3 alert unknown remote err type"
        type: bool
        required: False
    sslv3_alert_unspported_cert:
        description:
        - "Enable automatic packet-capture for sslv3 alert unspported cert"
        type: bool
        required: False
    ssl_ctx_has_no_default_ssl_version:
        description:
        - "Enable automatic packet-capture for ssl ctx has no default ssl version"
        type: bool
        required: False
    ssl_handshake_failure:
        description:
        - "Enable automatic packet-capture for ssl handshake failure"
        type: bool
        required: False
    ssl_library_has_no_ciphers:
        description:
        - "Enable automatic packet-capture for ssl library has no ciphers"
        type: bool
        required: False
    ssl_session_id_callback_failed:
        description:
        - "Enable automatic packet-capture for ssl session id callback failed"
        type: bool
        required: False
    ssl_session_id_conflict:
        description:
        - "Enable automatic packet-capture for ssl session id conflict"
        type: bool
        required: False
    ssl_session_id_context_too_long:
        description:
        - "Enable automatic packet-capture for ssl session id context too long"
        type: bool
        required: False
    ssl_session_id_has_bad_length:
        description:
        - "Enable automatic packet-capture for ssl session id has bad length"
        type: bool
        required: False
    ssl_session_id_is_different:
        description:
        - "Enable automatic packet-capture for ssl session id is different"
        type: bool
        required: False
    tlsv1_alert_access_denied:
        description:
        - "Enable automatic packet-capture for tlsv1 alert access denied"
        type: bool
        required: False
    tlsv1_alert_decode_error:
        description:
        - "Enable automatic packet-capture for tlsv1 alert decode error"
        type: bool
        required: False
    tlsv1_alert_decryption_failed:
        description:
        - "Enable automatic packet-capture for tlsv1 alert decryption failed"
        type: bool
        required: False
    tlsv1_alert_decrypt_error:
        description:
        - "Enable automatic packet-capture for tlsv1 alert decrypt error"
        type: bool
        required: False
    tlsv1_alert_export_restriction:
        description:
        - "Enable automatic packet-capture for tlsv1 alert export restriction"
        type: bool
        required: False
    tlsv1_alert_insufficient_security:
        description:
        - "Enable automatic packet-capture for tlsv1 alert insufficient security"
        type: bool
        required: False
    tlsv1_alert_internal_error:
        description:
        - "Enable automatic packet-capture for tlsv1 alert internal error"
        type: bool
        required: False
    tlsv1_alert_no_renegotiation:
        description:
        - "Enable automatic packet-capture for tlsv1 alert no renegotiation"
        type: bool
        required: False
    tlsv1_alert_protocol_version:
        description:
        - "Enable automatic packet-capture for tlsv1 alert protocol version"
        type: bool
        required: False
    tlsv1_alert_record_overflow:
        description:
        - "Enable automatic packet-capture for tlsv1 alert record overflow"
        type: bool
        required: False
    tlsv1_alert_unknown_ca:
        description:
        - "Enable automatic packet-capture for tlsv1 alert unknown ca"
        type: bool
        required: False
    tlsv1_alert_user_cancelled:
        description:
        - "Enable automatic packet-capture for tlsv1 alert user cancelled"
        type: bool
        required: False
    tls_client_cert_req_with_anon_cipher:
        description:
        - "Enable automatic packet-capture for tls client cert req with anon cipher"
        type: bool
        required: False
    tls_peer_did_not_respond_with_cert_list:
        description:
        - "Enable automatic packet-capture for tls peer did not respond with cert list"
        type: bool
        required: False
    tls_rsa_encrypted_value_length_is_wrong:
        description:
        - "Enable automatic packet-capture for tls rsa encrypted value length is wrong"
        type: bool
        required: False
    tried_to_use_unsupported_cipher:
        description:
        - "Enable automatic packet-capture for tried to use unsupported cipher"
        type: bool
        required: False
    unable_to_decode_dh_certs:
        description:
        - "Enable automatic packet-capture for unable to decode dh certs"
        type: bool
        required: False
    unable_to_extract_public_key:
        description:
        - "Enable automatic packet-capture for unable to extract public key"
        type: bool
        required: False
    unable_to_find_dh_parameters:
        description:
        - "Enable automatic packet-capture for unable to find dh parameters"
        type: bool
        required: False
    unable_to_find_public_key_parameters:
        description:
        - "Enable automatic packet-capture for unable to find public key parameters"
        type: bool
        required: False
    unable_to_find_ssl_method:
        description:
        - "Enable automatic packet-capture for unable to find ssl method"
        type: bool
        required: False
    unable_to_load_ssl2_md5_routines:
        description:
        - "Enable automatic packet-capture for unable to load ssl2 md5 routines"
        type: bool
        required: False
    unable_to_load_ssl3_md5_routines:
        description:
        - "Enable automatic packet-capture for unable to load ssl3 md5 routines"
        type: bool
        required: False
    unable_to_load_ssl3_sha1_routines:
        description:
        - "Enable automatic packet-capture for unable to load ssl3 sha1 routines"
        type: bool
        required: False
    unexpected_message:
        description:
        - "Enable automatic packet-capture for unexpected message"
        type: bool
        required: False
    unexpected_record:
        description:
        - "Enable automatic packet-capture for unexpected record"
        type: bool
        required: False
    uninitialized:
        description:
        - "Enable automatic packet-capture for uninitialized"
        type: bool
        required: False
    unknown_alert_type:
        description:
        - "Enable automatic packet-capture for unknown alert type"
        type: bool
        required: False
    unknown_certificate_type:
        description:
        - "Enable automatic packet-capture for unknown certificate type"
        type: bool
        required: False
    unknown_cipher_returned:
        description:
        - "Enable automatic packet-capture for unknown cipher returned"
        type: bool
        required: False
    unknown_cipher_type:
        description:
        - "Enable automatic packet-capture for unknown cipher type"
        type: bool
        required: False
    unknown_key_exchange_type:
        description:
        - "Enable automatic packet-capture for unknown key exchange type"
        type: bool
        required: False
    unknown_pkey_type:
        description:
        - "Enable automatic packet-capture for unknown pkey type"
        type: bool
        required: False
    unknown_protocol:
        description:
        - "Enable automatic packet-capture for unknown protocol"
        type: bool
        required: False
    unknown_remote_error_type:
        description:
        - "Enable automatic packet-capture for unknown remote error type"
        type: bool
        required: False
    unknown_ssl_version:
        description:
        - "Enable automatic packet-capture for unknown ssl version"
        type: bool
        required: False
    unknown_state:
        description:
        - "Enable automatic packet-capture for unknown state"
        type: bool
        required: False
    unsupported_cipher:
        description:
        - "Enable automatic packet-capture for unsupported cipher"
        type: bool
        required: False
    unsupported_compression_algorithm:
        description:
        - "Enable automatic packet-capture for unsupported compression algorithm"
        type: bool
        required: False
    unsupported_option:
        description:
        - "Enable automatic packet-capture for unsupported option"
        type: bool
        required: False
    unsupported_protocol:
        description:
        - "Enable automatic packet-capture for unsupported protocol"
        type: bool
        required: False
    unsupported_ssl_version:
        description:
        - "Enable automatic packet-capture for unsupported ssl version"
        type: bool
        required: False
    unsupported_status_type:
        description:
        - "Enable automatic packet-capture for unsupported status type"
        type: bool
        required: False
    write_bio_not_set:
        description:
        - "Enable automatic packet-capture for write bio not set"
        type: bool
        required: False
    wrong_cipher_returned:
        description:
        - "Enable automatic packet-capture for wrong cipher returned"
        type: bool
        required: False
    wrong_message_type:
        description:
        - "Enable automatic packet-capture for wrong message type"
        type: bool
        required: False
    wrong_counter_of_key_bits:
        description:
        - "Enable automatic packet-capture for wrong counter of key bits"
        type: bool
        required: False
    wrong_signature_length:
        description:
        - "Enable automatic packet-capture for wrong signature length"
        type: bool
        required: False
    wrong_signature_size:
        description:
        - "Enable automatic packet-capture for wrong signature size"
        type: bool
        required: False
    wrong_ssl_version:
        description:
        - "Enable automatic packet-capture for wrong ssl version"
        type: bool
        required: False
    wrong_version_counter:
        description:
        - "Enable automatic packet-capture for wrong version counter"
        type: bool
        required: False
    x509_lib:
        description:
        - "Enable automatic packet-capture for x509 lib"
        type: bool
        required: False
    x509_verification_setup_problems:
        description:
        - "Enable automatic packet-capture for x509 verification setup problems"
        type: bool
        required: False
    clienthello_tlsext:
        description:
        - "Enable automatic packet-capture for clienthello tlsext"
        type: bool
        required: False
    parse_tlsext:
        description:
        - "Enable automatic packet-capture for parse tlsext"
        type: bool
        required: False
    serverhello_tlsext:
        description:
        - "Enable automatic packet-capture for serverhello tlsext"
        type: bool
        required: False
    ssl3_ext_invalid_servername:
        description:
        - "Enable automatic packet-capture for ssl3 ext invalid servername"
        type: bool
        required: False
    ssl3_ext_invalid_servername_type:
        description:
        - "Enable automatic packet-capture for ssl3 ext invalid servername type"
        type: bool
        required: False
    multiple_sgc_restarts:
        description:
        - "Enable automatic packet-capture for multiple sgc restarts"
        type: bool
        required: False
    tls_invalid_ecpointformat_list:
        description:
        - "Enable automatic packet-capture for tls invalid ecpointformat list"
        type: bool
        required: False
    bad_ecc_cert:
        description:
        - "Enable automatic packet-capture for bad ecc cert"
        type: bool
        required: False
    bad_ecdsa_sig:
        description:
        - "Enable automatic packet-capture for bad ecdsa sig"
        type: bool
        required: False
    bad_ecpoint:
        description:
        - "Enable automatic packet-capture for bad ecpoint"
        type: bool
        required: False
    cookie_mismatch:
        description:
        - "Enable automatic packet-capture for cookie mismatch"
        type: bool
        required: False
    unsupported_elliptic_curve:
        description:
        - "Enable automatic packet-capture for unsupported elliptic curve"
        type: bool
        required: False
    no_required_digest:
        description:
        - "Enable automatic packet-capture for no required digest"
        type: bool
        required: False
    unsupported_digest_type:
        description:
        - "Enable automatic packet-capture for unsupported digest type"
        type: bool
        required: False
    bad_handshake_length:
        description:
        - "Enable automatic packet-capture for bad handshake length"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = [
    "app_data_in_handshake",
    "attempt_to_reuse_sess_in_diff_context",
    "bad_alert_record",
    "bad_authentication_type",
    "bad_change_cipher_spec",
    "bad_checksum",
    "bad_data_returned_by_callback",
    "bad_decompression",
    "bad_dh_g_length",
    "bad_dh_p_length",
    "bad_dh_pub_key_length",
    "bad_digest_length",
    "bad_dsa_signature",
    "bad_ecc_cert",
    "bad_ecdsa_sig",
    "bad_ecpoint",
    "bad_handshake_length",
    "bad_hello_request",
    "bad_length",
    "bad_mac_decode",
    "bad_message_type",
    "bad_packet_length",
    "bad_protocol_version_counter",
    "bad_response_argument",
    "bad_rsa_decrypt",
    "bad_rsa_e_length",
    "bad_rsa_encrypt",
    "bad_rsa_modulus_length",
    "bad_rsa_signature",
    "bad_signature",
    "bad_ssl_filetype",
    "bad_ssl_session_id_length",
    "bad_state",
    "bad_write_retry",
    "bio_not_set",
    "block_cipher_pad_is_wrong",
    "bn_lib",
    "ca_dn_length_mismatch",
    "ca_dn_too_long",
    "ccs_received_early",
    "cert_length_mismatch",
    "certificate_verify_failed",
    "challenge_is_different",
    "cipher_code_wrong_length",
    "cipher_or_hash_unavailable",
    "cipher_table_src_error",
    "clienthello_tlsext",
    "compressed_length_too_long",
    "compression_failure",
    "compression_library_error",
    "connection_id_is_different",
    "connection_type_not_set",
    "cookie_mismatch",
    "data_between_ccs_and_finished",
    "data_length_too_long",
    "decryption_failed",
    "decryption_failed_or_bad_record_mac",
    "dh_public_value_length_is_wrong",
    "digest_check_failed",
    "duration",
    "encrypted_length_too_long",
    "error_generating_tmp_rsa_key",
    "error_in_received_cipher_list",
    "excessive_message_size",
    "extra_data_in_message",
    "got_a_fin_before_a_ccs",
    "http_request",
    "https_proxy_request",
    "illegal_padding",
    "inappropriate_fallback",
    "invalid_challenge_length",
    "invalid_command",
    "invalid_purpose",
    "invalid_status_response",
    "invalid_trust",
    "key_arg_too_long",
    "krb5",
    "krb5_client_cc_principal",
    "krb5_client_get_cred",
    "krb5_client_init",
    "krb5_client_mk_req",
    "krb5_server_bad_ticket",
    "krb5_server_init",
    "krb5_server_rd_req",
    "krb5_server_tkt_expired",
    "krb5_server_tkt_not_yet_valid",
    "krb5_server_tkt_skew",
    "length_mismatch",
    "length_too_short",
    "library_bug",
    "library_has_no_ciphers",
    "mast_key_too_long",
    "message_too_long",
    "missing_dh_dsa_cert",
    "missing_dh_key",
    "missing_dh_rsa_cert",
    "missing_dsa_signing_cert",
    "missing_export_tmp_dh_key",
    "missing_export_tmp_rsa_key",
    "missing_rsa_certificate",
    "missing_rsa_encrypting_cert",
    "missing_rsa_signing_cert",
    "missing_tmp_dh_key",
    "missing_tmp_rsa_key",
    "missing_tmp_rsa_pkey",
    "missing_verify_message",
    "multiple_sgc_restarts",
    "no_certificate_assigned",
    "no_certificate_returned",
    "no_certificate_set",
    "no_certificate_specified",
    "no_certificates_returned",
    "no_cipher_list",
    "no_cipher_match",
    "no_ciphers_available",
    "no_ciphers_passed",
    "no_ciphers_specified",
    "no_client_cert_received",
    "no_compression_specified",
    "no_method_specified",
    "no_private_key_assigned",
    "no_privatekey",
    "no_protocols_available",
    "no_publickey",
    "no_required_digest",
    "no_shared_cipher",
    "no_verify_callback",
    "non_sslv2_initial_packet",
    "null_ssl_ctx",
    "null_ssl_method_passed",
    "old_session_cipher_not_returned",
    "packet_length_too_long",
    "parse_tlsext",
    "path_too_long",
    "peer_did_not_return_a_certificate",
    "peer_error",
    "peer_error_certificate",
    "peer_error_no_certificate",
    "peer_error_no_cipher",
    "peer_error_unsupported_certificate_type",
    "pre_mac_length_too_long",
    "problems_mapping_cipher_functions",
    "protocol_is_shutdown",
    "public_key_encrypt_error",
    "public_key_is_not_rsa",
    "public_key_not_rsa",
    "read_bio_not_set",
    "read_wrong_packet_type",
    "record_length_mismatch",
    "record_too_large",
    "record_too_small",
    "required_cipher_missing",
    "reuse_cert_length_not_zero",
    "reuse_cert_type_not_zero",
    "reuse_cipher_list_not_zero",
    "scsv_received_when_renegotiating",
    "serverhello_tlsext",
    "session_id_context_uninitialized",
    "short_read",
    "signature_for_non_signing_certificate",
    "ssl_ctx_has_no_default_ssl_version",
    "ssl_handshake_failure",
    "ssl_library_has_no_ciphers",
    "ssl_session_id_callback_failed",
    "ssl_session_id_conflict",
    "ssl_session_id_context_too_long",
    "ssl_session_id_has_bad_length",
    "ssl_session_id_is_different",
    "ssl2_connection_id_too_long",
    "ssl23_doing_session_id_reuse",
    "ssl3_ext_invalid_servername",
    "ssl3_ext_invalid_servername_type",
    "ssl3_session_id_too_long",
    "ssl3_session_id_too_short",
    "sslv3_alert_bad_certificate",
    "sslv3_alert_bad_record_mac",
    "sslv3_alert_certificate_expired",
    "sslv3_alert_certificate_revoked",
    "sslv3_alert_certificate_unknown",
    "sslv3_alert_decompression_failure",
    "sslv3_alert_handshake_failure",
    "sslv3_alert_illegal_parameter",
    "sslv3_alert_no_certificate",
    "sslv3_alert_peer_error_cert",
    "sslv3_alert_peer_error_no_cert",
    "sslv3_alert_peer_error_no_cipher",
    "sslv3_alert_peer_error_unsupp_cert_type",
    "sslv3_alert_unexpected_msg",
    "sslv3_alert_unknown_remote_err_type",
    "sslv3_alert_unspported_cert",
    "threshold_exceeded_by",
    "tls_client_cert_req_with_anon_cipher",
    "tls_invalid_ecpointformat_list",
    "tls_peer_did_not_respond_with_cert_list",
    "tls_rsa_encrypted_value_length_is_wrong",
    "tlsv1_alert_access_denied",
    "tlsv1_alert_decode_error",
    "tlsv1_alert_decrypt_error",
    "tlsv1_alert_decryption_failed",
    "tlsv1_alert_export_restriction",
    "tlsv1_alert_insufficient_security",
    "tlsv1_alert_internal_error",
    "tlsv1_alert_no_renegotiation",
    "tlsv1_alert_protocol_version",
    "tlsv1_alert_record_overflow",
    "tlsv1_alert_unknown_ca",
    "tlsv1_alert_user_cancelled",
    "tried_to_use_unsupported_cipher",
    "unable_to_decode_dh_certs",
    "unable_to_extract_public_key",
    "unable_to_find_dh_parameters",
    "unable_to_find_public_key_parameters",
    "unable_to_find_ssl_method",
    "unable_to_load_ssl2_md5_routines",
    "unable_to_load_ssl3_md5_routines",
    "unable_to_load_ssl3_sha1_routines",
    "unexpected_message",
    "unexpected_record",
    "uninitialized",
    "unknown_alert_type",
    "unknown_certificate_type",
    "unknown_cipher_returned",
    "unknown_cipher_type",
    "unknown_key_exchange_type",
    "unknown_pkey_type",
    "unknown_protocol",
    "unknown_remote_error_type",
    "unknown_ssl_version",
    "unknown_state",
    "unsupported_cipher",
    "unsupported_compression_algorithm",
    "unsupported_digest_type",
    "unsupported_elliptic_curve",
    "unsupported_option",
    "unsupported_protocol",
    "unsupported_ssl_version",
    "unsupported_status_type",
    "uuid",
    "write_bio_not_set",
    "wrong_cipher_returned",
    "wrong_counter_of_key_bits",
    "wrong_message_type",
    "wrong_signature_length",
    "wrong_signature_size",
    "wrong_ssl_version",
    "wrong_version_counter",
    "x509_lib",
    "x509_verification_setup_problems",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'threshold_exceeded_by': {
            'type': 'int',
        },
        'duration': {
            'type': 'int',
        },
        'app_data_in_handshake': {
            'type': 'bool',
        },
        'attempt_to_reuse_sess_in_diff_context': {
            'type': 'bool',
        },
        'bad_alert_record': {
            'type': 'bool',
        },
        'bad_authentication_type': {
            'type': 'bool',
        },
        'bad_change_cipher_spec': {
            'type': 'bool',
        },
        'bad_checksum': {
            'type': 'bool',
        },
        'bad_data_returned_by_callback': {
            'type': 'bool',
        },
        'bad_decompression': {
            'type': 'bool',
        },
        'bad_dh_g_length': {
            'type': 'bool',
        },
        'bad_dh_pub_key_length': {
            'type': 'bool',
        },
        'bad_dh_p_length': {
            'type': 'bool',
        },
        'bad_digest_length': {
            'type': 'bool',
        },
        'bad_dsa_signature': {
            'type': 'bool',
        },
        'bad_hello_request': {
            'type': 'bool',
        },
        'bad_length': {
            'type': 'bool',
        },
        'bad_mac_decode': {
            'type': 'bool',
        },
        'bad_message_type': {
            'type': 'bool',
        },
        'bad_packet_length': {
            'type': 'bool',
        },
        'bad_protocol_version_counter': {
            'type': 'bool',
        },
        'bad_response_argument': {
            'type': 'bool',
        },
        'bad_rsa_decrypt': {
            'type': 'bool',
        },
        'bad_rsa_encrypt': {
            'type': 'bool',
        },
        'bad_rsa_e_length': {
            'type': 'bool',
        },
        'bad_rsa_modulus_length': {
            'type': 'bool',
        },
        'bad_rsa_signature': {
            'type': 'bool',
        },
        'bad_signature': {
            'type': 'bool',
        },
        'bad_ssl_filetype': {
            'type': 'bool',
        },
        'bad_ssl_session_id_length': {
            'type': 'bool',
        },
        'bad_state': {
            'type': 'bool',
        },
        'bad_write_retry': {
            'type': 'bool',
        },
        'bio_not_set': {
            'type': 'bool',
        },
        'block_cipher_pad_is_wrong': {
            'type': 'bool',
        },
        'bn_lib': {
            'type': 'bool',
        },
        'ca_dn_length_mismatch': {
            'type': 'bool',
        },
        'ca_dn_too_long': {
            'type': 'bool',
        },
        'ccs_received_early': {
            'type': 'bool',
        },
        'certificate_verify_failed': {
            'type': 'bool',
        },
        'cert_length_mismatch': {
            'type': 'bool',
        },
        'challenge_is_different': {
            'type': 'bool',
        },
        'cipher_code_wrong_length': {
            'type': 'bool',
        },
        'cipher_or_hash_unavailable': {
            'type': 'bool',
        },
        'cipher_table_src_error': {
            'type': 'bool',
        },
        'compressed_length_too_long': {
            'type': 'bool',
        },
        'compression_failure': {
            'type': 'bool',
        },
        'compression_library_error': {
            'type': 'bool',
        },
        'connection_id_is_different': {
            'type': 'bool',
        },
        'connection_type_not_set': {
            'type': 'bool',
        },
        'data_between_ccs_and_finished': {
            'type': 'bool',
        },
        'data_length_too_long': {
            'type': 'bool',
        },
        'decryption_failed': {
            'type': 'bool',
        },
        'decryption_failed_or_bad_record_mac': {
            'type': 'bool',
        },
        'dh_public_value_length_is_wrong': {
            'type': 'bool',
        },
        'digest_check_failed': {
            'type': 'bool',
        },
        'encrypted_length_too_long': {
            'type': 'bool',
        },
        'error_generating_tmp_rsa_key': {
            'type': 'bool',
        },
        'error_in_received_cipher_list': {
            'type': 'bool',
        },
        'excessive_message_size': {
            'type': 'bool',
        },
        'extra_data_in_message': {
            'type': 'bool',
        },
        'got_a_fin_before_a_ccs': {
            'type': 'bool',
        },
        'https_proxy_request': {
            'type': 'bool',
        },
        'http_request': {
            'type': 'bool',
        },
        'illegal_padding': {
            'type': 'bool',
        },
        'inappropriate_fallback': {
            'type': 'bool',
        },
        'invalid_challenge_length': {
            'type': 'bool',
        },
        'invalid_command': {
            'type': 'bool',
        },
        'invalid_purpose': {
            'type': 'bool',
        },
        'invalid_status_response': {
            'type': 'bool',
        },
        'invalid_trust': {
            'type': 'bool',
        },
        'key_arg_too_long': {
            'type': 'bool',
        },
        'krb5': {
            'type': 'bool',
        },
        'krb5_client_cc_principal': {
            'type': 'bool',
        },
        'krb5_client_get_cred': {
            'type': 'bool',
        },
        'krb5_client_init': {
            'type': 'bool',
        },
        'krb5_client_mk_req': {
            'type': 'bool',
        },
        'krb5_server_bad_ticket': {
            'type': 'bool',
        },
        'krb5_server_init': {
            'type': 'bool',
        },
        'krb5_server_rd_req': {
            'type': 'bool',
        },
        'krb5_server_tkt_expired': {
            'type': 'bool',
        },
        'krb5_server_tkt_not_yet_valid': {
            'type': 'bool',
        },
        'krb5_server_tkt_skew': {
            'type': 'bool',
        },
        'length_mismatch': {
            'type': 'bool',
        },
        'length_too_short': {
            'type': 'bool',
        },
        'library_bug': {
            'type': 'bool',
        },
        'library_has_no_ciphers': {
            'type': 'bool',
        },
        'mast_key_too_long': {
            'type': 'bool',
        },
        'message_too_long': {
            'type': 'bool',
        },
        'missing_dh_dsa_cert': {
            'type': 'bool',
        },
        'missing_dh_key': {
            'type': 'bool',
        },
        'missing_dh_rsa_cert': {
            'type': 'bool',
        },
        'missing_dsa_signing_cert': {
            'type': 'bool',
        },
        'missing_export_tmp_dh_key': {
            'type': 'bool',
        },
        'missing_export_tmp_rsa_key': {
            'type': 'bool',
        },
        'missing_rsa_certificate': {
            'type': 'bool',
        },
        'missing_rsa_encrypting_cert': {
            'type': 'bool',
        },
        'missing_rsa_signing_cert': {
            'type': 'bool',
        },
        'missing_tmp_dh_key': {
            'type': 'bool',
        },
        'missing_tmp_rsa_key': {
            'type': 'bool',
        },
        'missing_tmp_rsa_pkey': {
            'type': 'bool',
        },
        'missing_verify_message': {
            'type': 'bool',
        },
        'non_sslv2_initial_packet': {
            'type': 'bool',
        },
        'no_certificates_returned': {
            'type': 'bool',
        },
        'no_certificate_assigned': {
            'type': 'bool',
        },
        'no_certificate_returned': {
            'type': 'bool',
        },
        'no_certificate_set': {
            'type': 'bool',
        },
        'no_certificate_specified': {
            'type': 'bool',
        },
        'no_ciphers_available': {
            'type': 'bool',
        },
        'no_ciphers_passed': {
            'type': 'bool',
        },
        'no_ciphers_specified': {
            'type': 'bool',
        },
        'no_cipher_list': {
            'type': 'bool',
        },
        'no_cipher_match': {
            'type': 'bool',
        },
        'no_client_cert_received': {
            'type': 'bool',
        },
        'no_compression_specified': {
            'type': 'bool',
        },
        'no_method_specified': {
            'type': 'bool',
        },
        'no_privatekey': {
            'type': 'bool',
        },
        'no_private_key_assigned': {
            'type': 'bool',
        },
        'no_protocols_available': {
            'type': 'bool',
        },
        'no_publickey': {
            'type': 'bool',
        },
        'no_shared_cipher': {
            'type': 'bool',
        },
        'no_verify_callback': {
            'type': 'bool',
        },
        'null_ssl_ctx': {
            'type': 'bool',
        },
        'null_ssl_method_passed': {
            'type': 'bool',
        },
        'old_session_cipher_not_returned': {
            'type': 'bool',
        },
        'packet_length_too_long': {
            'type': 'bool',
        },
        'path_too_long': {
            'type': 'bool',
        },
        'peer_did_not_return_a_certificate': {
            'type': 'bool',
        },
        'peer_error': {
            'type': 'bool',
        },
        'peer_error_certificate': {
            'type': 'bool',
        },
        'peer_error_no_certificate': {
            'type': 'bool',
        },
        'peer_error_no_cipher': {
            'type': 'bool',
        },
        'peer_error_unsupported_certificate_type': {
            'type': 'bool',
        },
        'pre_mac_length_too_long': {
            'type': 'bool',
        },
        'problems_mapping_cipher_functions': {
            'type': 'bool',
        },
        'protocol_is_shutdown': {
            'type': 'bool',
        },
        'public_key_encrypt_error': {
            'type': 'bool',
        },
        'public_key_is_not_rsa': {
            'type': 'bool',
        },
        'public_key_not_rsa': {
            'type': 'bool',
        },
        'read_bio_not_set': {
            'type': 'bool',
        },
        'read_wrong_packet_type': {
            'type': 'bool',
        },
        'record_length_mismatch': {
            'type': 'bool',
        },
        'record_too_large': {
            'type': 'bool',
        },
        'record_too_small': {
            'type': 'bool',
        },
        'required_cipher_missing': {
            'type': 'bool',
        },
        'reuse_cert_length_not_zero': {
            'type': 'bool',
        },
        'reuse_cert_type_not_zero': {
            'type': 'bool',
        },
        'reuse_cipher_list_not_zero': {
            'type': 'bool',
        },
        'scsv_received_when_renegotiating': {
            'type': 'bool',
        },
        'session_id_context_uninitialized': {
            'type': 'bool',
        },
        'short_read': {
            'type': 'bool',
        },
        'signature_for_non_signing_certificate': {
            'type': 'bool',
        },
        'ssl23_doing_session_id_reuse': {
            'type': 'bool',
        },
        'ssl2_connection_id_too_long': {
            'type': 'bool',
        },
        'ssl3_session_id_too_long': {
            'type': 'bool',
        },
        'ssl3_session_id_too_short': {
            'type': 'bool',
        },
        'sslv3_alert_bad_certificate': {
            'type': 'bool',
        },
        'sslv3_alert_bad_record_mac': {
            'type': 'bool',
        },
        'sslv3_alert_certificate_expired': {
            'type': 'bool',
        },
        'sslv3_alert_certificate_revoked': {
            'type': 'bool',
        },
        'sslv3_alert_certificate_unknown': {
            'type': 'bool',
        },
        'sslv3_alert_decompression_failure': {
            'type': 'bool',
        },
        'sslv3_alert_handshake_failure': {
            'type': 'bool',
        },
        'sslv3_alert_illegal_parameter': {
            'type': 'bool',
        },
        'sslv3_alert_no_certificate': {
            'type': 'bool',
        },
        'sslv3_alert_peer_error_cert': {
            'type': 'bool',
        },
        'sslv3_alert_peer_error_no_cert': {
            'type': 'bool',
        },
        'sslv3_alert_peer_error_no_cipher': {
            'type': 'bool',
        },
        'sslv3_alert_peer_error_unsupp_cert_type': {
            'type': 'bool',
        },
        'sslv3_alert_unexpected_msg': {
            'type': 'bool',
        },
        'sslv3_alert_unknown_remote_err_type': {
            'type': 'bool',
        },
        'sslv3_alert_unspported_cert': {
            'type': 'bool',
        },
        'ssl_ctx_has_no_default_ssl_version': {
            'type': 'bool',
        },
        'ssl_handshake_failure': {
            'type': 'bool',
        },
        'ssl_library_has_no_ciphers': {
            'type': 'bool',
        },
        'ssl_session_id_callback_failed': {
            'type': 'bool',
        },
        'ssl_session_id_conflict': {
            'type': 'bool',
        },
        'ssl_session_id_context_too_long': {
            'type': 'bool',
        },
        'ssl_session_id_has_bad_length': {
            'type': 'bool',
        },
        'ssl_session_id_is_different': {
            'type': 'bool',
        },
        'tlsv1_alert_access_denied': {
            'type': 'bool',
        },
        'tlsv1_alert_decode_error': {
            'type': 'bool',
        },
        'tlsv1_alert_decryption_failed': {
            'type': 'bool',
        },
        'tlsv1_alert_decrypt_error': {
            'type': 'bool',
        },
        'tlsv1_alert_export_restriction': {
            'type': 'bool',
        },
        'tlsv1_alert_insufficient_security': {
            'type': 'bool',
        },
        'tlsv1_alert_internal_error': {
            'type': 'bool',
        },
        'tlsv1_alert_no_renegotiation': {
            'type': 'bool',
        },
        'tlsv1_alert_protocol_version': {
            'type': 'bool',
        },
        'tlsv1_alert_record_overflow': {
            'type': 'bool',
        },
        'tlsv1_alert_unknown_ca': {
            'type': 'bool',
        },
        'tlsv1_alert_user_cancelled': {
            'type': 'bool',
        },
        'tls_client_cert_req_with_anon_cipher': {
            'type': 'bool',
        },
        'tls_peer_did_not_respond_with_cert_list': {
            'type': 'bool',
        },
        'tls_rsa_encrypted_value_length_is_wrong': {
            'type': 'bool',
        },
        'tried_to_use_unsupported_cipher': {
            'type': 'bool',
        },
        'unable_to_decode_dh_certs': {
            'type': 'bool',
        },
        'unable_to_extract_public_key': {
            'type': 'bool',
        },
        'unable_to_find_dh_parameters': {
            'type': 'bool',
        },
        'unable_to_find_public_key_parameters': {
            'type': 'bool',
        },
        'unable_to_find_ssl_method': {
            'type': 'bool',
        },
        'unable_to_load_ssl2_md5_routines': {
            'type': 'bool',
        },
        'unable_to_load_ssl3_md5_routines': {
            'type': 'bool',
        },
        'unable_to_load_ssl3_sha1_routines': {
            'type': 'bool',
        },
        'unexpected_message': {
            'type': 'bool',
        },
        'unexpected_record': {
            'type': 'bool',
        },
        'uninitialized': {
            'type': 'bool',
        },
        'unknown_alert_type': {
            'type': 'bool',
        },
        'unknown_certificate_type': {
            'type': 'bool',
        },
        'unknown_cipher_returned': {
            'type': 'bool',
        },
        'unknown_cipher_type': {
            'type': 'bool',
        },
        'unknown_key_exchange_type': {
            'type': 'bool',
        },
        'unknown_pkey_type': {
            'type': 'bool',
        },
        'unknown_protocol': {
            'type': 'bool',
        },
        'unknown_remote_error_type': {
            'type': 'bool',
        },
        'unknown_ssl_version': {
            'type': 'bool',
        },
        'unknown_state': {
            'type': 'bool',
        },
        'unsupported_cipher': {
            'type': 'bool',
        },
        'unsupported_compression_algorithm': {
            'type': 'bool',
        },
        'unsupported_option': {
            'type': 'bool',
        },
        'unsupported_protocol': {
            'type': 'bool',
        },
        'unsupported_ssl_version': {
            'type': 'bool',
        },
        'unsupported_status_type': {
            'type': 'bool',
        },
        'write_bio_not_set': {
            'type': 'bool',
        },
        'wrong_cipher_returned': {
            'type': 'bool',
        },
        'wrong_message_type': {
            'type': 'bool',
        },
        'wrong_counter_of_key_bits': {
            'type': 'bool',
        },
        'wrong_signature_length': {
            'type': 'bool',
        },
        'wrong_signature_size': {
            'type': 'bool',
        },
        'wrong_ssl_version': {
            'type': 'bool',
        },
        'wrong_version_counter': {
            'type': 'bool',
        },
        'x509_lib': {
            'type': 'bool',
        },
        'x509_verification_setup_problems': {
            'type': 'bool',
        },
        'clienthello_tlsext': {
            'type': 'bool',
        },
        'parse_tlsext': {
            'type': 'bool',
        },
        'serverhello_tlsext': {
            'type': 'bool',
        },
        'ssl3_ext_invalid_servername': {
            'type': 'bool',
        },
        'ssl3_ext_invalid_servername_type': {
            'type': 'bool',
        },
        'multiple_sgc_restarts': {
            'type': 'bool',
        },
        'tls_invalid_ecpointformat_list': {
            'type': 'bool',
        },
        'bad_ecc_cert': {
            'type': 'bool',
        },
        'bad_ecdsa_sig': {
            'type': 'bool',
        },
        'bad_ecpoint': {
            'type': 'bool',
        },
        'cookie_mismatch': {
            'type': 'bool',
        },
        'unsupported_elliptic_curve': {
            'type': 'bool',
        },
        'no_required_digest': {
            'type': 'bool',
        },
        'unsupported_digest_type': {
            'type': 'bool',
        },
        'bad_handshake_length': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/slb-ssl-error/trigger-stats-rate"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/slb-ssl-error/trigger-stats-rate"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-rate"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-rate"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-rate"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("trigger-stats-rate", module.params,
                               AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
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
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "trigger-stats-rate"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "trigger-stats-rate-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
