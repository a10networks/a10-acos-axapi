#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_server_ssl_counters
description:
    - Server side SSL Vport Statistics
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            vserver:
                description:
                - "virtual server name"
                type: str
            port:
                description:
                - "Virtual Port"
                type: int
            cumulative_sessions:
                description:
                - "Cumulative SSL sessions"
                type: int
            ssl3_rsa_des_192_cbc3_sha_id:
                description:
                - "SSL3_RSA_DES_192_CBC3_SHA Cipher ID"
                type: str
            ssl3_rsa_des_40_cbc_sha_id:
                description:
                - "SSL3_RSA_DES_40_CBC_SHA Cipher ID"
                type: str
            ssl3_rsa_des_64_cbc_sha_id:
                description:
                - "SSL3_RSA_DES_64_CBC_SHA Cipher ID"
                type: str
            ssl3_rsa_rc4_128_md5_id:
                description:
                - "SSL3_RSA_RC4_128_MD5 Cipher ID"
                type: str
            ssl3_rsa_rc4_128_sha_id:
                description:
                - "SSL3_RSA_RC4_128_SHA Cipher ID"
                type: str
            ssl3_rsa_rc4_40_md5_id:
                description:
                - "SSL3_RSA_RC4_40_MD5 Cipher ID"
                type: str
            tls1_dhe_rsa_aes_128_gcm_sha256_id:
                description:
                - "TLS1_DHE_RSA_AES_128_GCM_SHA256 Cipher ID"
                type: str
            tls1_dhe_rsa_aes_128_sha_id:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA Cipher ID"
                type: str
            tls1_dhe_rsa_aes_128_sha256_id:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA256 Cipher ID"
                type: str
            tls1_dhe_rsa_aes_256_gcm_sha384_id:
                description:
                - "TLS1_DHE_RSA_AES_256_GCM_SHA384 Cipher ID"
                type: str
            tls1_dhe_rsa_aes_256_sha_id:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA Cipher ID"
                type: str
            tls1_dhe_rsa_aes_256_sha256_id:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_128_gcm_sha256_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_128_sha_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_128_sha256_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_256_sha384_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA384 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_256_gcm_sha384_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_aes_256_sha_id:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_128_gcm_sha256_id:
                description:
                - "TLS1_ECDHE_RSA_AES_128_GCM_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_128_sha_id:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_128_sha256_id:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_256_sha384_id:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA384 Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_256_gcm_sha384_id:
                description:
                - "TLS1_ECDHE_RSA_AES_256_GCM_SHA384 Cipher ID"
                type: str
            tls1_ecdhe_rsa_aes_256_sha_id:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA Cipher ID"
                type: str
            tls1_rsa_aes_128_gcm_sha256_id:
                description:
                - "TLS1_RSA_AES_128_GCM_SHA256 Cipher ID"
                type: str
            tls1_rsa_aes_128_sha_id:
                description:
                - "TLS1_RSA_AES_128_SHA Cipher ID"
                type: str
            tls1_rsa_aes_128_sha256_id:
                description:
                - "TLS1_RSA_AES_128_SHA256 Cipher ID"
                type: str
            tls1_rsa_aes_256_gcm_sha384_id:
                description:
                - "TLS1_RSA_AES_256_GCM_SHA384 Cipher ID"
                type: str
            tls1_rsa_aes_256_sha_id:
                description:
                - "TLS1_RSA_AES_256_SHA Cipher ID"
                type: str
            tls1_rsa_aes_256_sha256_id:
                description:
                - "TLS1_RSA_AES_256_SHA256 Cipher ID"
                type: str
            tls1_rsa_export1024_rc4_56_md5_id:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_MD5 Cipher ID"
                type: str
            tls1_rsa_export1024_rc4_56_sha_id:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_SHA Cipher ID"
                type: str
            tls1_ecdhe_rsa_chacha20_poly1305_sha256_id:
                description:
                - "TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256 Cipher ID"
                type: str
            tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_id:
                description:
                - "TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 Cipher ID"
                type: str
            tls1_dhe_rsa_chacha20_poly1305_sha256_id:
                description:
                - "TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256 Cipher ID"
                type: str
            ssl3_rsa_des_192_cbc3_sha_successes:
                description:
                - "SSL3_RSA_DES_192_CBC3_SHA Successes"
                type: int
            ssl3_rsa_des_40_cbc_sha_successes:
                description:
                - "SSL3_RSA_DES_40_CBC_SHA Successes"
                type: int
            ssl3_rsa_des_64_cbc_sha_successes:
                description:
                - "SSL3_RSA_DES_64_CBC_SHA Successes"
                type: int
            ssl3_rsa_rc4_128_md5_successes:
                description:
                - "SSL3_RSA_RC4_128_MD5 Successes"
                type: int
            ssl3_rsa_rc4_128_sha_successes:
                description:
                - "SSL3_RSA_RC4_128_SHA Successes"
                type: int
            ssl3_rsa_rc4_40_md5_successes:
                description:
                - "SSL3_RSA_RC4_40_MD5 Successes"
                type: int
            tls1_dhe_rsa_aes_128_gcm_sha256_successes:
                description:
                - "TLS1_DHE_RSA_AES_128_GCM_SHA256 Successes"
                type: int
            tls1_dhe_rsa_aes_128_sha_successes:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA Successes"
                type: int
            tls1_dhe_rsa_aes_128_sha256_successes:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA256 Successes"
                type: int
            tls1_dhe_rsa_aes_256_gcm_sha384_successes:
                description:
                - "TLS1_DHE_RSA_AES_256_GCM_SHA384 Successes"
                type: int
            tls1_dhe_rsa_aes_256_sha_successes:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA Successes"
                type: int
            tls1_dhe_rsa_aes_256_sha256_successes:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA256 Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_128_gcm_sha256_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256 Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_128_sha_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_128_sha256_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA256 Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_256_sha384_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA384 Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_256_gcm_sha384_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384 Successes"
                type: int
            tls1_ecdhe_ecdsa_aes_256_sha_successes:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA Successes"
                type: int
            tls1_ecdhe_rsa_aes_128_gcm_sha256_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_128_GCM_SHA256 Successes"
                type: int
            tls1_ecdhe_rsa_aes_128_sha_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA Successes"
                type: int
            tls1_ecdhe_rsa_aes_128_sha256_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA256 Successes"
                type: int
            tls1_ecdhe_rsa_aes_256_sha384_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA384 Successes"
                type: int
            tls1_ecdhe_rsa_aes_256_gcm_sha384_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_256_GCM_SHA384 Successes"
                type: int
            tls1_ecdhe_rsa_aes_256_sha_successes:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA Successes"
                type: int
            tls1_rsa_aes_128_gcm_sha256_successes:
                description:
                - "TLS1_RSA_AES_128_GCM_SHA256 Successes"
                type: int
            tls1_rsa_aes_128_sha_successes:
                description:
                - "TLS1_RSA_AES_128_SHA Successes"
                type: int
            tls1_rsa_aes_128_sha256_successes:
                description:
                - "TLS1_RSA_AES_128_SHA256 Successes"
                type: int
            tls1_rsa_aes_256_gcm_sha384_successes:
                description:
                - "TLS1_RSA_AES_256_GCM_SHA384 Successes"
                type: int
            tls1_rsa_aes_256_sha_successes:
                description:
                - "TLS1_RSA_AES_256_SHA Successes"
                type: int
            tls1_rsa_aes_256_sha256_successes:
                description:
                - "TLS1_RSA_AES_256_SHA256 Successes"
                type: int
            tls1_rsa_export1024_rc4_56_md5_successes:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_MD5 Successes"
                type: int
            tls1_rsa_export1024_rc4_56_sha_successes:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_SHA Successes"
                type: int
            tls1_ecdhe_rsa_chacha20_poly1305_sha256_successes:
                description:
                - "TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256 Cipher successes"
                type: int
            tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_successes:
                description:
                - "TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 Cipher successes"
                type: int
            tls1_dhe_rsa_chacha20_poly1305_sha256_successes:
                description:
                - "TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256 Cipher successes"
                type: int
            ssl3_rsa_des_192_cbc3_sha_failures:
                description:
                - "SSL3_RSA_DES_192_CBC3_SHA Failures"
                type: int
            ssl3_rsa_des_40_cbc_sha_failures:
                description:
                - "SSL3_RSA_DES_40_CBC_SHA Failures"
                type: int
            ssl3_rsa_des_64_cbc_sha_failures:
                description:
                - "SSL3_RSA_DES_64_CBC_SHA Failures"
                type: int
            ssl3_rsa_rc4_128_md5_failures:
                description:
                - "SSL3_RSA_RC4_128_MD5 Failures"
                type: int
            ssl3_rsa_rc4_128_sha_failures:
                description:
                - "SSL3_RSA_RC4_128_SHA Failures"
                type: int
            ssl3_rsa_rc4_40_md5_failures:
                description:
                - "SSL3_RSA_RC4_40_MD5 Failures"
                type: int
            tls1_dhe_rsa_aes_128_gcm_sha256_failures:
                description:
                - "TLS1_DHE_RSA_AES_128_GCM_SHA256 Failures"
                type: int
            tls1_dhe_rsa_aes_128_sha_failures:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA Failures"
                type: int
            tls1_dhe_rsa_aes_128_sha256_failures:
                description:
                - "TLS1_DHE_RSA_AES_128_SHA256 Failures"
                type: int
            tls1_dhe_rsa_aes_256_gcm_sha384_failures:
                description:
                - "TLS1_DHE_RSA_AES_256_GCM_SHA384 Failures"
                type: int
            tls1_dhe_rsa_aes_256_sha_failures:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA Failures"
                type: int
            tls1_dhe_rsa_aes_256_sha256_failures:
                description:
                - "TLS1_DHE_RSA_AES_256_SHA256 Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_128_gcm_sha256_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256 Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_128_sha_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_128_sha256_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_128_SHA256 Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_256_sha384_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA384 Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_256_gcm_sha384_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384 Failures"
                type: int
            tls1_ecdhe_ecdsa_aes_256_sha_failures:
                description:
                - "TLS1_ECDHE_ECDSA_AES_256_SHA Failures"
                type: int
            tls1_ecdhe_rsa_aes_128_gcm_sha256_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_128_GCM_SHA256 Failures"
                type: int
            tls1_ecdhe_rsa_aes_128_sha_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA Failures"
                type: int
            tls1_ecdhe_rsa_aes_128_sha256_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_128_SHA256 Failures"
                type: int
            tls1_ecdhe_rsa_aes_256_sha384_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA384 Failures"
                type: int
            tls1_ecdhe_rsa_aes_256_gcm_sha384_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_256_GCM_SHA384 Failures"
                type: int
            tls1_ecdhe_rsa_aes_256_sha_failures:
                description:
                - "TLS1_ECDHE_RSA_AES_256_SHA Failures"
                type: int
            tls1_rsa_aes_128_gcm_sha256_failures:
                description:
                - "TLS1_RSA_AES_128_GCM_SHA256 Failures"
                type: int
            tls1_rsa_aes_128_sha_failures:
                description:
                - "TLS1_RSA_AES_128_SHA Failures"
                type: int
            tls1_rsa_aes_128_sha256_failures:
                description:
                - "TLS1_RSA_AES_128_SHA256 Failures"
                type: int
            tls1_rsa_aes_256_gcm_sha384_failures:
                description:
                - "TLS1_RSA_AES_256_GCM_SHA384 Failures"
                type: int
            tls1_rsa_aes_256_sha_failures:
                description:
                - "TLS1_RSA_AES_256_SHA Failures"
                type: int
            tls1_rsa_aes_256_sha256_failures:
                description:
                - "TLS1_RSA_AES_256_SHA256 Failures"
                type: int
            tls1_rsa_export1024_rc4_56_md5_failures:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_MD5 Failures"
                type: int
            tls1_rsa_export1024_rc4_56_sha_failures:
                description:
                - "TLS1_RSA_EXPORT1024_RC4_56_SHA Failures"
                type: int
            tls1_ecdhe_rsa_chacha20_poly1305_sha256_failures:
                description:
                - "TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256 Cipher failures"
                type: int
            tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_failures:
                description:
                - "TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 Cipher failures"
                type: int
            tls1_dhe_rsa_chacha20_poly1305_sha256_failures:
                description:
                - "TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256 Cipher failures"
                type: int
            kex_rsa_512_successes:
                description:
                - "Successful 512-bit RSA key exchanges"
                type: int
            kex_rsa_1024_successes:
                description:
                - "Successful 1024-bit RSA key exchanges"
                type: int
            kex_rsa_2048_successes:
                description:
                - "Successful 2048-bit RSA key exchanges"
                type: int
            kex_rsa_4096_successes:
                description:
                - "Successful 4096-bit RSA key exchanges"
                type: int
            kex_rsa_512_failures:
                description:
                - "Failed 512-bit RSA key exchanges"
                type: int
            kex_rsa_1024_failures:
                description:
                - "Failed 1024-bit RSA key exchanges"
                type: int
            kex_rsa_2048_failures:
                description:
                - "Failed 2048-bit RSA key exchanges"
                type: int
            kex_rsa_4096_failures:
                description:
                - "Failed 4096-bit RSA key exchanges"
                type: int
            kex_ecdhe_secp256r1_successes:
                description:
                - "Successful secp256r1 ECDHE key exchanges"
                type: int
            kex_ecdhe_secp384r1_successes:
                description:
                - "Successful secp384r1 ECDHE key exchanges"
                type: int
            kex_ecdhe_secp256r1_failures:
                description:
                - "Failed secp256r1 ECDHE key exchanges"
                type: int
            kex_ecdhe_secp384r1_failures:
                description:
                - "Failed secp384r1 ECDHE key exchanges"
                type: int
            kex_dhe_512_successes:
                description:
                - "Successful 512-bit DHE key exchanges"
                type: int
            kex_dhe_1024_successes:
                description:
                - "Successful 1024-bit DHE key exchanges"
                type: int
            kex_dhe_2048_successes:
                description:
                - "Successful 2048-bit DHE key exchanges"
                type: int
            kex_dhe_512_failures:
                description:
                - "Failed 512-bit DHE key exchanges"
                type: int
            kex_dhe_1024_failures:
                description:
                - "Failed 1024-bit DHE key exchanges"
                type: int
            kex_dhe_2048_failures:
                description:
                - "Failed 2048-bit DHE key exchanges"
                type: int
            ssl2_successes:
                description:
                - "Successful SSL2 connections"
                type: int
            ssl3_successes:
                description:
                - "Successful SSL3 connections"
                type: int
            tls10_successes:
                description:
                - "Successful TLS1.0 connections"
                type: int
            tls11_successes:
                description:
                - "Successful TLS1.1 connections"
                type: int
            tls12_successes:
                description:
                - "Successful TLS1.2 connections"
                type: int
            ssl2_failures:
                description:
                - "Failed SSL2 connections"
                type: int
            ssl3_failures:
                description:
                - "Failed SSL3 connections"
                type: int
            tls10_failures:
                description:
                - "Failed TLS1.0 connections"
                type: int
            tls11_failures:
                description:
                - "Failed TLS1.1 connections"
                type: int
            tls12_failures:
                description:
                - "Failed TLS1.2 connections"
                type: int
            sess_cache_new:
                description:
                - "Session cache new entries"
                type: int
            sess_cache_hit:
                description:
                - "Session cache hits"
                type: int
            sess_cache_miss:
                description:
                - "Session cache misses"
                type: int
            sess_cache_timeout:
                description:
                - "Session cache timeouts"
                type: int
            sess_cache_curr_conn:
                description:
                - "Session cache current connections"
                type: int
            hs_failures:
                description:
                - "Total handshake failures"
                type: int
            cert_vfy:
                description:
                - "Sent certificate verify for authentication"
                type: int
            hs_avg_time:
                description:
                - "Average handshake time in milliseconds"
                type: int
            renegotiation_total:
                description:
                - "Total renegotiations"
                type: int
            renego_ssl2_successes:
                description:
                - "Successful SSL2 renegotiations"
                type: int
            renego_ssl3_successes:
                description:
                - "Successful SSL3 renegotiations"
                type: int
            renego_tls10_successes:
                description:
                - "Successful TLS1.0 renegotiations"
                type: int
            renego_tls11_successes:
                description:
                - "Successful TLS1.1 renegotiations"
                type: int
            renego_tls12_successes:
                description:
                - "Successful TLS1.2 renegotiations"
                type: int
            renego_ssl2_failures:
                description:
                - "Failed SSL2 renegotiations"
                type: int
            renego_ssl3_failures:
                description:
                - "Failed SSL3 renegotiations"
                type: int
            renego_tls10_failures:
                description:
                - "Failed TLS1.0 renegotiations"
                type: int
            renego_tls11_failures:
                description:
                - "Failed TLS1.1 renegotiations"
                type: int
            renego_tls12_failures:
                description:
                - "Failed TLS1.2 renegotiations"
                type: int

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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "uuid",
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
        'uuid': {
            'type': 'str',
        },
        'oper': {
            'type': 'dict',
            'vserver': {
                'type': 'str',
            },
            'port': {
                'type': 'int',
            },
            'cumulative_sessions': {
                'type': 'int',
            },
            'ssl3_rsa_des_192_cbc3_sha_id': {
                'type': 'str',
            },
            'ssl3_rsa_des_40_cbc_sha_id': {
                'type': 'str',
            },
            'ssl3_rsa_des_64_cbc_sha_id': {
                'type': 'str',
            },
            'ssl3_rsa_rc4_128_md5_id': {
                'type': 'str',
            },
            'ssl3_rsa_rc4_128_sha_id': {
                'type': 'str',
            },
            'ssl3_rsa_rc4_40_md5_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_128_gcm_sha256_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_128_sha_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_128_sha256_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_256_gcm_sha384_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_256_sha_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_aes_256_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_128_gcm_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha384_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_256_gcm_sha384_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_128_gcm_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_128_sha_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_128_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_256_sha384_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_256_gcm_sha384_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_aes_256_sha_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_128_gcm_sha256_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_128_sha_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_128_sha256_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_256_gcm_sha384_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_256_sha_id': {
                'type': 'str',
            },
            'tls1_rsa_aes_256_sha256_id': {
                'type': 'str',
            },
            'tls1_rsa_export1024_rc4_56_md5_id': {
                'type': 'str',
            },
            'tls1_rsa_export1024_rc4_56_sha_id': {
                'type': 'str',
            },
            'tls1_ecdhe_rsa_chacha20_poly1305_sha256_id': {
                'type': 'str',
            },
            'tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_id': {
                'type': 'str',
            },
            'tls1_dhe_rsa_chacha20_poly1305_sha256_id': {
                'type': 'str',
            },
            'ssl3_rsa_des_192_cbc3_sha_successes': {
                'type': 'int',
            },
            'ssl3_rsa_des_40_cbc_sha_successes': {
                'type': 'int',
            },
            'ssl3_rsa_des_64_cbc_sha_successes': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_128_md5_successes': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_128_sha_successes': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_40_md5_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_gcm_sha256_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_sha_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_sha256_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_gcm_sha384_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_sha_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_gcm_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha384_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_gcm_sha384_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_gcm_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_sha_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_sha384_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_gcm_sha384_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_sha_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_gcm_sha256_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_sha_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_sha256_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_gcm_sha384_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_sha_successes': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_sha256_successes': {
                'type': 'int',
            },
            'tls1_rsa_export1024_rc4_56_md5_successes': {
                'type': 'int',
            },
            'tls1_rsa_export1024_rc4_56_sha_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_chacha20_poly1305_sha256_successes': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_successes': {
                'type': 'int',
            },
            'tls1_dhe_rsa_chacha20_poly1305_sha256_successes': {
                'type': 'int',
            },
            'ssl3_rsa_des_192_cbc3_sha_failures': {
                'type': 'int',
            },
            'ssl3_rsa_des_40_cbc_sha_failures': {
                'type': 'int',
            },
            'ssl3_rsa_des_64_cbc_sha_failures': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_128_md5_failures': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_128_sha_failures': {
                'type': 'int',
            },
            'ssl3_rsa_rc4_40_md5_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_gcm_sha256_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_sha_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_128_sha256_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_gcm_sha384_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_sha_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_aes_256_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_gcm_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_128_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha384_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_gcm_sha384_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_aes_256_sha_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_gcm_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_sha_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_128_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_sha384_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_gcm_sha384_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_aes_256_sha_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_gcm_sha256_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_sha_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_128_sha256_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_gcm_sha384_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_sha_failures': {
                'type': 'int',
            },
            'tls1_rsa_aes_256_sha256_failures': {
                'type': 'int',
            },
            'tls1_rsa_export1024_rc4_56_md5_failures': {
                'type': 'int',
            },
            'tls1_rsa_export1024_rc4_56_sha_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_rsa_chacha20_poly1305_sha256_failures': {
                'type': 'int',
            },
            'tls1_ecdhe_ecdsa_chacha20_poly1305_sha256_failures': {
                'type': 'int',
            },
            'tls1_dhe_rsa_chacha20_poly1305_sha256_failures': {
                'type': 'int',
            },
            'kex_rsa_512_successes': {
                'type': 'int',
            },
            'kex_rsa_1024_successes': {
                'type': 'int',
            },
            'kex_rsa_2048_successes': {
                'type': 'int',
            },
            'kex_rsa_4096_successes': {
                'type': 'int',
            },
            'kex_rsa_512_failures': {
                'type': 'int',
            },
            'kex_rsa_1024_failures': {
                'type': 'int',
            },
            'kex_rsa_2048_failures': {
                'type': 'int',
            },
            'kex_rsa_4096_failures': {
                'type': 'int',
            },
            'kex_ecdhe_secp256r1_successes': {
                'type': 'int',
            },
            'kex_ecdhe_secp384r1_successes': {
                'type': 'int',
            },
            'kex_ecdhe_secp256r1_failures': {
                'type': 'int',
            },
            'kex_ecdhe_secp384r1_failures': {
                'type': 'int',
            },
            'kex_dhe_512_successes': {
                'type': 'int',
            },
            'kex_dhe_1024_successes': {
                'type': 'int',
            },
            'kex_dhe_2048_successes': {
                'type': 'int',
            },
            'kex_dhe_512_failures': {
                'type': 'int',
            },
            'kex_dhe_1024_failures': {
                'type': 'int',
            },
            'kex_dhe_2048_failures': {
                'type': 'int',
            },
            'ssl2_successes': {
                'type': 'int',
            },
            'ssl3_successes': {
                'type': 'int',
            },
            'tls10_successes': {
                'type': 'int',
            },
            'tls11_successes': {
                'type': 'int',
            },
            'tls12_successes': {
                'type': 'int',
            },
            'ssl2_failures': {
                'type': 'int',
            },
            'ssl3_failures': {
                'type': 'int',
            },
            'tls10_failures': {
                'type': 'int',
            },
            'tls11_failures': {
                'type': 'int',
            },
            'tls12_failures': {
                'type': 'int',
            },
            'sess_cache_new': {
                'type': 'int',
            },
            'sess_cache_hit': {
                'type': 'int',
            },
            'sess_cache_miss': {
                'type': 'int',
            },
            'sess_cache_timeout': {
                'type': 'int',
            },
            'sess_cache_curr_conn': {
                'type': 'int',
            },
            'hs_failures': {
                'type': 'int',
            },
            'cert_vfy': {
                'type': 'int',
            },
            'hs_avg_time': {
                'type': 'int',
            },
            'renegotiation_total': {
                'type': 'int',
            },
            'renego_ssl2_successes': {
                'type': 'int',
            },
            'renego_ssl3_successes': {
                'type': 'int',
            },
            'renego_tls10_successes': {
                'type': 'int',
            },
            'renego_tls11_successes': {
                'type': 'int',
            },
            'renego_tls12_successes': {
                'type': 'int',
            },
            'renego_ssl2_failures': {
                'type': 'int',
            },
            'renego_ssl3_failures': {
                'type': 'int',
            },
            'renego_tls10_failures': {
                'type': 'int',
            },
            'renego_tls11_failures': {
                'type': 'int',
            },
            'renego_tls12_failures': {
                'type': 'int',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server-ssl-counters"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server-ssl-counters"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
        call_result = _post(module, new_url(module))
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config):
    try:
        call_result = _post(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
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
                  axapi_calls=[])

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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
