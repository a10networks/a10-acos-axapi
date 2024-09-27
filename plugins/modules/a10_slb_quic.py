#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_quic
description:
    - Show QUIC Statistics
author: A10 Networks
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'client_conn_attempted'= Client connection attempted;
          'client_conn_handshake'= Client connection handshake; 'client_conn_created'=
          Client connection created; 'client_conn_local_closed'= Client connection local
          closed; 'client_conn_remote_closed'= Client connection remote closed;
          'client_conn_failed'= Client connection failed; 'server_conn_attempted'= Server
          connection attempted; 'server_conn_handshake'= Server connection handshake;
          'server_conn_created'= Server connection created; 'server_conn_local_closed'=
          Server connection local closed; 'server_conn_remote_closed'= Server connection
          remote closed; 'server_conn_failed'= Server connection failed;
          'q_conn_created'= Q connection created; 'q_conn_freed'= Q connection freed;
          'local_bi_stream_current'= Current local bi-stream; 'remote_bi_stream_current'=
          Current remote bi-stream; 'local_bi_stream_created'= Local bi-stream created;
          'remote_bi_stream_created'= Remote bi-stream created; 'local_bi_stream_closed'=
          Local bi-stream closed; 'remote_bi_stream_closed'= Remote bi-stream closed;
          'local_uni_stream_current'= Current local uni-stream;
          'remote_uni_stream_current'= Current remote uni-stream;
          'local_uni_stream_created'= Local uni-stream created;
          'remote_uni_stream_created'= Remote uni-stream created;
          'local_uni_stream_closed'= Local uni-stream closed; 'remote_uni_stream_closed'=
          Remote uni-stream closed; 'stream_error'= Stream error;
          'stream_fail_to_insert'= Stream fail to insert; 'padding_frame_rx'= padding
          frame receive; 'padding_frame_tx'= padding frame send; 'ping_frame_rx'= ping
          frame receive; 'ping_frame_tx'= ping frame send; 'ack_frame_rx'= ack frame
          receive; 'ack_frame_tx'= ack frame send; 'ack_ecn_frame_rx'= ack enc frame
          receive; 'ack_ecn_frame_tx'= ack enc frame send; 'stream_rst_frame_rx'= stream
          reset frame receive; 'stream_rst_frame_tx'= stream reset frame send;
          'stream_stop_frame_rx'= stream stop frame receive; 'stream_stop_frame_tx'=
          stream stop frame send; 'crypto_frame_rx'= crypto frame receive;
          'crypto_frame_tx'= crypto frame send; 'new_token_frame_rx'= new token frame
          receive; 'new_token_frame_tx'= new token frame send; 'stream_frame_rx'= stream
          frame receive; 'stream_frame_tx'= stream frame send; 'stream_09_frame_rx'=
          stream 09 frame receive; 'stream_09_frame_tx'= stream 09 frame send;
          'stream_0a_frame_rx'= stream 0a frame receive; 'stream_0a_frame_tx'= stream 0a
          frame send; 'stream_0b_frame_rx'= stream 0b frame receive;
          'stream_0b_frame_tx'= stream 0b frame send; 'stream_0c_frame_rx'= stream 0c
          frame receive; 'stream_0c_frame_tx'= stream 0c frame send;
          'stream_0d_frame_rx'= stream 0d frame receive; 'stream_0d_frame_tx'= stream 0d
          frame send; 'stream_0e_frame_rx'= stream 0e frame receive;
          'stream_0e_frame_tx'= stream 0e frame send; 'stream_0f_frame_rx'= stream 0f
          frame receive; 'stream_0f_frame_tx'= stream 0f frame send; 'max_data_frame_rx'=
          max data frame receive; 'max_data_frame_tx'= max data frame send;
          'max_stream_data_frame_rx'= max stream data frame receive;
          'max_stream_data_frame_tx'= max stream data frame send;
          'max_bi_stream_frame_rx'= max bi stream frame receive;
          'max_bi_stream_frame_tx'= max bi stream frame send; 'max_uni_stream_frame_rx'=
          max uni stream frame receive; 'max_uni_stream_frame_tx'= max uni stream frame
          send; 'data_blocked_frame_rx'= data blocked frame receive;
          'data_blocked_frame_tx'= data blocked frame send;
          'stream_data_blocked_frame_rx'= stream data blocked frame receive;
          'stream_data_blocked_frame_tx'= stream data blocked frame send;
          'bi_stream_data_blocked_frame_rx'= bi stream data blocked frame receive;
          'bi_stream_data_blocked_frame_tx'= bi stream data blocked frame send;
          'uni_stream_data_blocked_frame_rx'= uni stream data blocked frame receive;
          'uni_stream_data_blocked_frame_tx'= uni stream data blocked frame send;
          'new_conn_id_frame_rx'= new conn id frame receive; 'new_conn_id_frame_tx'= new
          conn id frame send; 'retire_conn_id_frame_rx'= retire conn id frame receive;
          'retire_conn_id_frame_tx'= retire conn id frame send;
          'path_challenge_frame_rx'= path challenge frame receive;
          'path_challenge_frame_tx'= path challenge frame send; 'path_response_frame_rx'=
          path response frame receive; 'path_response_frame_tx'= path response frame
          send; 'conn_close_frame_rx'= conn close frame receive; 'conn_close_frame_tx'=
          conn close frame send; 'app_conn_close_frame_rx'= app conn close frame receive;
          'app_conn_close_frame_tx'= app conn close frame send;
          'handshake_done_frame_rx'= handshake done frame receive;
          'handshake_done_frame_tx'= handshake done frame send; 'unknown_frame'= Unknown
          frame; 'stream_fin_receive'= Stream FIN receive; 'stream_fin_up'= Stream FIN
          up; 'stream_fin_down'= Stream FIN down; 'stream_fin_send'= Stream FIN send;
          'stream_congest'= Stream congest; 'stream_open'= Stream open;
          'stream_pause_data'= Stream pause data; 'stream_resume_data'= Stream resume
          data; 'stream_not_send'= Stream not send; 'stream_stop_send'= Stream stop send;
          'stream_created'= Stream created; 'stream_freed'= Stream freed; 'INITIAL_rx'=
          INITIAL receive; 'INITIAL_tx'= INITIAL send; 'RTT_0_rx'= RTT_0 receive;
          'RTT_0_tx'= RTT_0 send; 'HANDSHAKE_rx'= HANDSHAKE receive; 'HANDSHAKE_tx'=
          HANDSHAKE send; 'RETRY_rx'= RETRY receive; 'RETRY_tx'= RETRY send; 'VER_rx'=
          Version receive; 'VER_tx'= Version send; 'RTT_updated'= RTT updated;
          'Needs_ack'= Needs ACK; 'Delayed_ack'= Delayed ACK; 'Packet_rx'= Packet
          receive; 'Packet_tx'= Packet send; 'Packet_tx_failed'= Packet send failed;
          'Congest_wnd_inc'= Congestion window increase; 'Congest_wnd_dec'= Congestion
          window decrease; 'No_congest_wnd'= No congestion window; 'Burst_limited'= Burst
          limited; 'Packet_loop_limited'= Packet loop limited; 'Receive_wnd_limited'=
          Receive window limited; 'Parse_error'= Parse error; 'Error_close'= Conn closed
          of error; 'Unknown_scid'= Unknown scid; 'Dcid_mismatch'= Dcid mismatch;
          'Packet_too_short'= Packet_too_short; 'Invalid_version'= Invalid version;
          'Invalid_Packet'= Invalid packet; 'Invalid_conn_match'= Invalid conn match;
          'Invalid_session_packet'= Invalid session packet; 'Stateless_reset'= Stateless
          resert; 'Packet_lost'= Packet lost; 'Packet_drop'= Packet drop;
          'Packet_retransmit'= Packet retransmit; 'Packet_out_of_order'= Packet out of
          order; 'Quic_packet_drop'= Quic packet drop; 'Encode_error'= Encode error;
          'Decode_failed'= Decode failed; 'Decode_stream_error'= Decode stream error;
          'Exceed_flow_control'= Exceed flow control; 'Crypto_stream_not_found'= Crypto
          stream not found; 'Exceed_max_stream_id'= Exceed_max_stream_id;
          'Stream_id_mismatch'= Stream_id_mismatch; 'Ack_delay_huge'= Ack_delay_huge;
          'Ack_rng_huge_1'= Ack_rng_huge_1; 'Ack_rng_huge_2'= Ack_rng_huge_2;
          'Ack_rng_huge_3'= Ack_rng_huge_3; 'Too_noisy_fuzzing'= Too_noisy_fuzzing;
          'Max_stream_too_big'= Max_stream_too_big; 'Stream_blocked'= Stream_blocked;
          'New_conn_id_len_zero'= New_conn_id_len_zero; 'New_conn_id_len_non_zero'=
          New_conn_id_len_non_zero; 'Illegal_stream_len'= Illegal_stream_len;
          'Illegal_reason_len'= Illegal_reason_len; 'Illegal_seq'= Illegal_seq;
          'Illegal_rpt'= Illegal_rpt; 'Illegal_len'= Illegal_len; 'Illegal_token_len'=
          Illegal_token_len; 'Cannot_insert_cid'= Cannot_insert_cid; 'Cannot_insert_srt'=
          Cannot_insert_srt; 'Cannot_retire_cid'= Cannot_retire_cid; 'No_next_scid'=
          No_next_scid; 'Token_len_too_long'= Token_len_too_long;
          'Server_receive_new_token'= Server_receive_new_token; 'Zero_frame_packet'=
          Zero_frame_packet;"
                type: str
            counters2:
                description:
                - "'Err_frame_dec1'= Err_frame_dec1; 'Err_frame_dec'= Err_frame_dec;
          'Err_frame_decb'= Err_frame_decb; 'Err_frame_final_size'= Err_frame_final_size;
          'Err_flow_control'= Err_flow_control; 'Err_protocol_violation'=
          Err_protocol_violation; 'Server_rx_handshake_done'= Server_rx_handshake_done;
          'Pkt_acked_failed'= Pkt_acked_failed; 'Pn_insert_failed'= Pn insert failed;
          'Pn_delete_failed'= Pn delete failed; 'Acked_packet_freed'= Acked packet freed;
          'Tx_buffer_enq'= Tx buffer enqueued; 'Tx_buffer_deq'= Tx buffer dequeued;
          'App_buffer_enq'= App buffer enqueued; 'App_buffer_deq'= App buffer dequeued;
          'App_buffer_queue_full'= App buffer queue full; 'Iov_buffer_bind'= Iov buffer
          bind; 'Iov_buffer_unbind'= Iov buffer unbind; 'Iov_buffer_dup'= Iov buffer dup;
          'Iov_alloc_len'= Iov alloc len; 'Iov_IO'= Iov IO; 'Iov_System'= Iov System;
          'No_tx_queue'= No tx queue; 'wsocket_created'= wsocket created;
          'wsocket_closed'= wsocket closed; 'a10_socket_created'= a10 socket created;
          'a10_socket_closed'= a10 socket closed; 'No_a10_socket'= no a10 socket;
          'No_other_side_socket'= no other side socket; 'No_w_engine'= no w engine;
          'No_w_socket'= no w socket; 'on_ld_timeout'= lost detection timeout;
          'idle_alarm'= conn idle timeout; 'ack_alarm'= ack timeout; 'close_alarm'= close
          timeout; 'delay_alarm'= delay timeout; 'quic_malloc'= QUIC malloc; 'quic_free'=
          QUIC free; 'quic_malloc_failure'= QUIC malloc failure; 'quick_malloc_failure'=
          quick malloc failure; 'quic_lb'= QUIC LB; 'cid_zero'= CID Zero; 'cid_cpu_hash'=
          CID CPU Hash; 'invalid_cid_sig'= Invalid CID Signature; 'key_update_rx'= QUIC
          TLS key update received; 'key_update_tx'= QUIC TLS key update sent;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            session_list:
                description:
                - "Field session_list"
                type: list
            total_sessions:
                description:
                - "Field total_sessions"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            client_conn_attempted:
                description:
                - "Client connection attempted"
                type: str
            client_conn_handshake:
                description:
                - "Client connection handshake"
                type: str
            client_conn_created:
                description:
                - "Client connection created"
                type: str
            client_conn_local_closed:
                description:
                - "Client connection local closed"
                type: str
            client_conn_remote_closed:
                description:
                - "Client connection remote closed"
                type: str
            client_conn_failed:
                description:
                - "Client connection failed"
                type: str
            server_conn_attempted:
                description:
                - "Server connection attempted"
                type: str
            server_conn_handshake:
                description:
                - "Server connection handshake"
                type: str
            server_conn_created:
                description:
                - "Server connection created"
                type: str
            server_conn_local_closed:
                description:
                - "Server connection local closed"
                type: str
            server_conn_remote_closed:
                description:
                - "Server connection remote closed"
                type: str
            server_conn_failed:
                description:
                - "Server connection failed"
                type: str
            q_conn_created:
                description:
                - "Q connection created"
                type: str
            q_conn_freed:
                description:
                - "Q connection freed"
                type: str
            local_bi_stream_current:
                description:
                - "Current local bi-stream"
                type: str
            remote_bi_stream_current:
                description:
                - "Current remote bi-stream"
                type: str
            local_bi_stream_created:
                description:
                - "Local bi-stream created"
                type: str
            remote_bi_stream_created:
                description:
                - "Remote bi-stream created"
                type: str
            local_bi_stream_closed:
                description:
                - "Local bi-stream closed"
                type: str
            remote_bi_stream_closed:
                description:
                - "Remote bi-stream closed"
                type: str
            local_uni_stream_current:
                description:
                - "Current local uni-stream"
                type: str
            remote_uni_stream_current:
                description:
                - "Current remote uni-stream"
                type: str
            local_uni_stream_created:
                description:
                - "Local uni-stream created"
                type: str
            remote_uni_stream_created:
                description:
                - "Remote uni-stream created"
                type: str
            local_uni_stream_closed:
                description:
                - "Local uni-stream closed"
                type: str
            remote_uni_stream_closed:
                description:
                - "Remote uni-stream closed"
                type: str
            stream_error:
                description:
                - "Stream error"
                type: str
            stream_fail_to_insert:
                description:
                - "Stream fail to insert"
                type: str
            padding_frame_rx:
                description:
                - "padding frame receive"
                type: str
            padding_frame_tx:
                description:
                - "padding frame send"
                type: str
            ping_frame_rx:
                description:
                - "ping frame receive"
                type: str
            ping_frame_tx:
                description:
                - "ping frame send"
                type: str
            ack_frame_rx:
                description:
                - "ack frame receive"
                type: str
            ack_frame_tx:
                description:
                - "ack frame send"
                type: str
            ack_ecn_frame_rx:
                description:
                - "ack enc frame receive"
                type: str
            ack_ecn_frame_tx:
                description:
                - "ack enc frame send"
                type: str
            stream_rst_frame_rx:
                description:
                - "stream reset frame receive"
                type: str
            stream_rst_frame_tx:
                description:
                - "stream reset frame send"
                type: str
            stream_stop_frame_rx:
                description:
                - "stream stop frame receive"
                type: str
            stream_stop_frame_tx:
                description:
                - "stream stop frame send"
                type: str
            crypto_frame_rx:
                description:
                - "crypto frame receive"
                type: str
            crypto_frame_tx:
                description:
                - "crypto frame send"
                type: str
            new_token_frame_rx:
                description:
                - "new token frame receive"
                type: str
            new_token_frame_tx:
                description:
                - "new token frame send"
                type: str
            stream_frame_rx:
                description:
                - "stream frame receive"
                type: str
            stream_frame_tx:
                description:
                - "stream frame send"
                type: str
            stream_09_frame_rx:
                description:
                - "stream 09 frame receive"
                type: str
            stream_09_frame_tx:
                description:
                - "stream 09 frame send"
                type: str
            stream_0a_frame_rx:
                description:
                - "stream 0a frame receive"
                type: str
            stream_0a_frame_tx:
                description:
                - "stream 0a frame send"
                type: str
            stream_0b_frame_rx:
                description:
                - "stream 0b frame receive"
                type: str
            stream_0b_frame_tx:
                description:
                - "stream 0b frame send"
                type: str
            stream_0c_frame_rx:
                description:
                - "stream 0c frame receive"
                type: str
            stream_0c_frame_tx:
                description:
                - "stream 0c frame send"
                type: str
            stream_0d_frame_rx:
                description:
                - "stream 0d frame receive"
                type: str
            stream_0d_frame_tx:
                description:
                - "stream 0d frame send"
                type: str
            stream_0e_frame_rx:
                description:
                - "stream 0e frame receive"
                type: str
            stream_0e_frame_tx:
                description:
                - "stream 0e frame send"
                type: str
            stream_0f_frame_rx:
                description:
                - "stream 0f frame receive"
                type: str
            stream_0f_frame_tx:
                description:
                - "stream 0f frame send"
                type: str
            max_data_frame_rx:
                description:
                - "max data frame receive"
                type: str
            max_data_frame_tx:
                description:
                - "max data frame send"
                type: str
            max_stream_data_frame_rx:
                description:
                - "max stream data frame receive"
                type: str
            max_stream_data_frame_tx:
                description:
                - "max stream data frame send"
                type: str
            max_bi_stream_frame_rx:
                description:
                - "max bi stream frame receive"
                type: str
            max_bi_stream_frame_tx:
                description:
                - "max bi stream frame send"
                type: str
            max_uni_stream_frame_rx:
                description:
                - "max uni stream frame receive"
                type: str
            max_uni_stream_frame_tx:
                description:
                - "max uni stream frame send"
                type: str
            data_blocked_frame_rx:
                description:
                - "data blocked frame receive"
                type: str
            data_blocked_frame_tx:
                description:
                - "data blocked frame send"
                type: str
            stream_data_blocked_frame_rx:
                description:
                - "stream data blocked frame receive"
                type: str
            stream_data_blocked_frame_tx:
                description:
                - "stream data blocked frame send"
                type: str
            bi_stream_data_blocked_frame_rx:
                description:
                - "bi stream data blocked frame receive"
                type: str
            bi_stream_data_blocked_frame_tx:
                description:
                - "bi stream data blocked frame send"
                type: str
            uni_stream_data_blocked_frame_rx:
                description:
                - "uni stream data blocked frame receive"
                type: str
            uni_stream_data_blocked_frame_tx:
                description:
                - "uni stream data blocked frame send"
                type: str
            new_conn_id_frame_rx:
                description:
                - "new conn id frame receive"
                type: str
            new_conn_id_frame_tx:
                description:
                - "new conn id frame send"
                type: str
            retire_conn_id_frame_rx:
                description:
                - "retire conn id frame receive"
                type: str
            retire_conn_id_frame_tx:
                description:
                - "retire conn id frame send"
                type: str
            path_challenge_frame_rx:
                description:
                - "path challenge frame receive"
                type: str
            path_challenge_frame_tx:
                description:
                - "path challenge frame send"
                type: str
            path_response_frame_rx:
                description:
                - "path response frame receive"
                type: str
            path_response_frame_tx:
                description:
                - "path response frame send"
                type: str
            conn_close_frame_rx:
                description:
                - "conn close frame receive"
                type: str
            conn_close_frame_tx:
                description:
                - "conn close frame send"
                type: str
            app_conn_close_frame_rx:
                description:
                - "app conn close frame receive"
                type: str
            app_conn_close_frame_tx:
                description:
                - "app conn close frame send"
                type: str
            handshake_done_frame_rx:
                description:
                - "handshake done frame receive"
                type: str
            handshake_done_frame_tx:
                description:
                - "handshake done frame send"
                type: str
            unknown_frame:
                description:
                - "Unknown frame"
                type: str
            stream_fin_receive:
                description:
                - "Stream FIN receive"
                type: str
            stream_fin_up:
                description:
                - "Stream FIN up"
                type: str
            stream_fin_down:
                description:
                - "Stream FIN down"
                type: str
            stream_fin_send:
                description:
                - "Stream FIN send"
                type: str
            stream_congest:
                description:
                - "Stream congest"
                type: str
            stream_open:
                description:
                - "Stream open"
                type: str
            stream_pause_data:
                description:
                - "Stream pause data"
                type: str
            stream_resume_data:
                description:
                - "Stream resume data"
                type: str
            stream_not_send:
                description:
                - "Stream not send"
                type: str
            stream_stop_send:
                description:
                - "Stream stop send"
                type: str
            stream_created:
                description:
                - "Stream created"
                type: str
            stream_freed:
                description:
                - "Stream freed"
                type: str
            INITIAL_rx:
                description:
                - "INITIAL receive"
                type: str
            INITIAL_tx:
                description:
                - "INITIAL send"
                type: str
            RTT_0_rx:
                description:
                - "RTT_0 receive"
                type: str
            RTT_0_tx:
                description:
                - "RTT_0 send"
                type: str
            HANDSHAKE_rx:
                description:
                - "HANDSHAKE receive"
                type: str
            HANDSHAKE_tx:
                description:
                - "HANDSHAKE send"
                type: str
            RETRY_rx:
                description:
                - "RETRY receive"
                type: str
            RETRY_tx:
                description:
                - "RETRY send"
                type: str
            VER_rx:
                description:
                - "Version receive"
                type: str
            VER_tx:
                description:
                - "Version send"
                type: str
            RTT_updated:
                description:
                - "RTT updated"
                type: str
            Needs_ack:
                description:
                - "Needs ACK"
                type: str
            Delayed_ack:
                description:
                - "Delayed ACK"
                type: str
            Packet_rx:
                description:
                - "Packet receive"
                type: str
            Packet_tx:
                description:
                - "Packet send"
                type: str
            Packet_tx_failed:
                description:
                - "Packet send failed"
                type: str
            Congest_wnd_inc:
                description:
                - "Congestion window increase"
                type: str
            Congest_wnd_dec:
                description:
                - "Congestion window decrease"
                type: str
            No_congest_wnd:
                description:
                - "No congestion window"
                type: str
            Burst_limited:
                description:
                - "Burst limited"
                type: str
            Packet_loop_limited:
                description:
                - "Packet loop limited"
                type: str
            Receive_wnd_limited:
                description:
                - "Receive window limited"
                type: str
            Parse_error:
                description:
                - "Parse error"
                type: str
            Error_close:
                description:
                - "Conn closed of error"
                type: str
            Unknown_scid:
                description:
                - "Unknown scid"
                type: str
            Dcid_mismatch:
                description:
                - "Dcid mismatch"
                type: str
            Packet_too_short:
                description:
                - "Packet_too_short"
                type: str
            Invalid_version:
                description:
                - "Invalid version"
                type: str
            Invalid_Packet:
                description:
                - "Invalid packet"
                type: str
            Invalid_conn_match:
                description:
                - "Invalid conn match"
                type: str
            Invalid_session_packet:
                description:
                - "Invalid session packet"
                type: str
            Stateless_reset:
                description:
                - "Stateless resert"
                type: str
            Packet_lost:
                description:
                - "Packet lost"
                type: str
            Packet_drop:
                description:
                - "Packet drop"
                type: str
            Packet_retransmit:
                description:
                - "Packet retransmit"
                type: str
            Packet_out_of_order:
                description:
                - "Packet out of order"
                type: str
            Quic_packet_drop:
                description:
                - "Quic packet drop"
                type: str
            Encode_error:
                description:
                - "Encode error"
                type: str
            Decode_failed:
                description:
                - "Decode failed"
                type: str
            Decode_stream_error:
                description:
                - "Decode stream error"
                type: str
            Exceed_flow_control:
                description:
                - "Exceed flow control"
                type: str
            Crypto_stream_not_found:
                description:
                - "Crypto stream not found"
                type: str
            Exceed_max_stream_id:
                description:
                - "Exceed_max_stream_id"
                type: str
            Stream_id_mismatch:
                description:
                - "Stream_id_mismatch"
                type: str
            Ack_delay_huge:
                description:
                - "Ack_delay_huge"
                type: str
            Ack_rng_huge_1:
                description:
                - "Ack_rng_huge_1"
                type: str
            Ack_rng_huge_2:
                description:
                - "Ack_rng_huge_2"
                type: str
            Ack_rng_huge_3:
                description:
                - "Ack_rng_huge_3"
                type: str
            Too_noisy_fuzzing:
                description:
                - "Too_noisy_fuzzing"
                type: str
            Max_stream_too_big:
                description:
                - "Max_stream_too_big"
                type: str
            Stream_blocked:
                description:
                - "Stream_blocked"
                type: str
            New_conn_id_len_zero:
                description:
                - "New_conn_id_len_zero"
                type: str
            New_conn_id_len_non_zero:
                description:
                - "New_conn_id_len_non_zero"
                type: str
            Illegal_stream_len:
                description:
                - "Illegal_stream_len"
                type: str
            Illegal_reason_len:
                description:
                - "Illegal_reason_len"
                type: str
            Illegal_seq:
                description:
                - "Illegal_seq"
                type: str
            Illegal_rpt:
                description:
                - "Illegal_rpt"
                type: str
            Illegal_len:
                description:
                - "Illegal_len"
                type: str
            Illegal_token_len:
                description:
                - "Illegal_token_len"
                type: str
            Cannot_insert_cid:
                description:
                - "Cannot_insert_cid"
                type: str
            Cannot_insert_srt:
                description:
                - "Cannot_insert_srt"
                type: str
            Cannot_retire_cid:
                description:
                - "Cannot_retire_cid"
                type: str
            No_next_scid:
                description:
                - "No_next_scid"
                type: str
            Token_len_too_long:
                description:
                - "Token_len_too_long"
                type: str
            Server_receive_new_token:
                description:
                - "Server_receive_new_token"
                type: str
            Zero_frame_packet:
                description:
                - "Zero_frame_packet"
                type: str
            Err_frame_dec1:
                description:
                - "Err_frame_dec1"
                type: str
            Err_frame_dec:
                description:
                - "Err_frame_dec"
                type: str
            Err_frame_decb:
                description:
                - "Err_frame_decb"
                type: str
            Err_frame_final_size:
                description:
                - "Err_frame_final_size"
                type: str
            Err_flow_control:
                description:
                - "Err_flow_control"
                type: str
            Err_protocol_violation:
                description:
                - "Err_protocol_violation"
                type: str
            Server_rx_handshake_done:
                description:
                - "Server_rx_handshake_done"
                type: str
            Pkt_acked_failed:
                description:
                - "Pkt_acked_failed"
                type: str
            Pn_insert_failed:
                description:
                - "Pn insert failed"
                type: str
            Pn_delete_failed:
                description:
                - "Pn delete failed"
                type: str
            Acked_packet_freed:
                description:
                - "Acked packet freed"
                type: str
            Tx_buffer_enq:
                description:
                - "Tx buffer enqueued"
                type: str
            Tx_buffer_deq:
                description:
                - "Tx buffer dequeued"
                type: str
            App_buffer_enq:
                description:
                - "App buffer enqueued"
                type: str
            App_buffer_deq:
                description:
                - "App buffer dequeued"
                type: str
            App_buffer_queue_full:
                description:
                - "App buffer queue full"
                type: str
            Iov_buffer_bind:
                description:
                - "Iov buffer bind"
                type: str
            Iov_buffer_unbind:
                description:
                - "Iov buffer unbind"
                type: str
            Iov_buffer_dup:
                description:
                - "Iov buffer dup"
                type: str
            Iov_alloc_len:
                description:
                - "Iov alloc len"
                type: str
            Iov_IO:
                description:
                - "Iov IO"
                type: str
            Iov_System:
                description:
                - "Iov System"
                type: str
            No_tx_queue:
                description:
                - "No tx queue"
                type: str
            wsocket_created:
                description:
                - "wsocket created"
                type: str
            wsocket_closed:
                description:
                - "wsocket closed"
                type: str
            a10_socket_created:
                description:
                - "a10 socket created"
                type: str
            a10_socket_closed:
                description:
                - "a10 socket closed"
                type: str
            No_a10_socket:
                description:
                - "no a10 socket"
                type: str
            No_other_side_socket:
                description:
                - "no other side socket"
                type: str
            No_w_engine:
                description:
                - "no w engine"
                type: str
            No_w_socket:
                description:
                - "no w socket"
                type: str
            on_ld_timeout:
                description:
                - "lost detection timeout"
                type: str
            idle_alarm:
                description:
                - "conn idle timeout"
                type: str
            ack_alarm:
                description:
                - "ack timeout"
                type: str
            close_alarm:
                description:
                - "close timeout"
                type: str
            delay_alarm:
                description:
                - "delay timeout"
                type: str
            quic_malloc:
                description:
                - "QUIC malloc"
                type: str
            quic_free:
                description:
                - "QUIC free"
                type: str
            quic_malloc_failure:
                description:
                - "QUIC malloc failure"
                type: str
            quick_malloc_failure:
                description:
                - "quick malloc failure"
                type: str
            quic_lb:
                description:
                - "QUIC LB"
                type: str
            cid_zero:
                description:
                - "CID Zero"
                type: str
            cid_cpu_hash:
                description:
                - "CID CPU Hash"
                type: str
            invalid_cid_sig:
                description:
                - "Invalid CID Signature"
                type: str
            key_update_rx:
                description:
                - "QUIC TLS key update received"
                type: str
            key_update_tx:
                description:
                - "QUIC TLS key update sent"
                type: str

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
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'client_conn_attempted', 'client_conn_handshake', 'client_conn_created', 'client_conn_local_closed', 'client_conn_remote_closed', 'client_conn_failed', 'server_conn_attempted', 'server_conn_handshake', 'server_conn_created', 'server_conn_local_closed', 'server_conn_remote_closed', 'server_conn_failed', 'q_conn_created',
                    'q_conn_freed', 'local_bi_stream_current', 'remote_bi_stream_current', 'local_bi_stream_created', 'remote_bi_stream_created', 'local_bi_stream_closed', 'remote_bi_stream_closed', 'local_uni_stream_current', 'remote_uni_stream_current', 'local_uni_stream_created', 'remote_uni_stream_created', 'local_uni_stream_closed',
                    'remote_uni_stream_closed', 'stream_error', 'stream_fail_to_insert', 'padding_frame_rx', 'padding_frame_tx', 'ping_frame_rx', 'ping_frame_tx', 'ack_frame_rx', 'ack_frame_tx', 'ack_ecn_frame_rx', 'ack_ecn_frame_tx', 'stream_rst_frame_rx', 'stream_rst_frame_tx', 'stream_stop_frame_rx', 'stream_stop_frame_tx', 'crypto_frame_rx',
                    'crypto_frame_tx', 'new_token_frame_rx', 'new_token_frame_tx', 'stream_frame_rx', 'stream_frame_tx', 'stream_09_frame_rx', 'stream_09_frame_tx', 'stream_0a_frame_rx', 'stream_0a_frame_tx', 'stream_0b_frame_rx', 'stream_0b_frame_tx', 'stream_0c_frame_rx', 'stream_0c_frame_tx', 'stream_0d_frame_rx', 'stream_0d_frame_tx',
                    'stream_0e_frame_rx', 'stream_0e_frame_tx', 'stream_0f_frame_rx', 'stream_0f_frame_tx', 'max_data_frame_rx', 'max_data_frame_tx', 'max_stream_data_frame_rx', 'max_stream_data_frame_tx', 'max_bi_stream_frame_rx', 'max_bi_stream_frame_tx', 'max_uni_stream_frame_rx', 'max_uni_stream_frame_tx', 'data_blocked_frame_rx',
                    'data_blocked_frame_tx', 'stream_data_blocked_frame_rx', 'stream_data_blocked_frame_tx', 'bi_stream_data_blocked_frame_rx', 'bi_stream_data_blocked_frame_tx', 'uni_stream_data_blocked_frame_rx', 'uni_stream_data_blocked_frame_tx', 'new_conn_id_frame_rx', 'new_conn_id_frame_tx', 'retire_conn_id_frame_rx',
                    'retire_conn_id_frame_tx', 'path_challenge_frame_rx', 'path_challenge_frame_tx', 'path_response_frame_rx', 'path_response_frame_tx', 'conn_close_frame_rx', 'conn_close_frame_tx', 'app_conn_close_frame_rx', 'app_conn_close_frame_tx', 'handshake_done_frame_rx', 'handshake_done_frame_tx', 'unknown_frame', 'stream_fin_receive',
                    'stream_fin_up', 'stream_fin_down', 'stream_fin_send', 'stream_congest', 'stream_open', 'stream_pause_data', 'stream_resume_data', 'stream_not_send', 'stream_stop_send', 'stream_created', 'stream_freed', 'INITIAL_rx', 'INITIAL_tx', 'RTT_0_rx', 'RTT_0_tx', 'HANDSHAKE_rx', 'HANDSHAKE_tx', 'RETRY_rx', 'RETRY_tx', 'VER_rx',
                    'VER_tx', 'RTT_updated', 'Needs_ack', 'Delayed_ack', 'Packet_rx', 'Packet_tx', 'Packet_tx_failed', 'Congest_wnd_inc', 'Congest_wnd_dec', 'No_congest_wnd', 'Burst_limited', 'Packet_loop_limited', 'Receive_wnd_limited', 'Parse_error', 'Error_close', 'Unknown_scid', 'Dcid_mismatch', 'Packet_too_short', 'Invalid_version',
                    'Invalid_Packet', 'Invalid_conn_match', 'Invalid_session_packet', 'Stateless_reset', 'Packet_lost', 'Packet_drop', 'Packet_retransmit', 'Packet_out_of_order', 'Quic_packet_drop', 'Encode_error', 'Decode_failed', 'Decode_stream_error', 'Exceed_flow_control', 'Crypto_stream_not_found', 'Exceed_max_stream_id', 'Stream_id_mismatch',
                    'Ack_delay_huge', 'Ack_rng_huge_1', 'Ack_rng_huge_2', 'Ack_rng_huge_3', 'Too_noisy_fuzzing', 'Max_stream_too_big', 'Stream_blocked', 'New_conn_id_len_zero', 'New_conn_id_len_non_zero', 'Illegal_stream_len', 'Illegal_reason_len', 'Illegal_seq', 'Illegal_rpt', 'Illegal_len', 'Illegal_token_len', 'Cannot_insert_cid',
                    'Cannot_insert_srt', 'Cannot_retire_cid', 'No_next_scid', 'Token_len_too_long', 'Server_receive_new_token', 'Zero_frame_packet'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'Err_frame_dec1', 'Err_frame_dec', 'Err_frame_decb', 'Err_frame_final_size', 'Err_flow_control', 'Err_protocol_violation', 'Server_rx_handshake_done', 'Pkt_acked_failed', 'Pn_insert_failed', 'Pn_delete_failed', 'Acked_packet_freed', 'Tx_buffer_enq', 'Tx_buffer_deq', 'App_buffer_enq', 'App_buffer_deq', 'App_buffer_queue_full',
                    'Iov_buffer_bind', 'Iov_buffer_unbind', 'Iov_buffer_dup', 'Iov_alloc_len', 'Iov_IO', 'Iov_System', 'No_tx_queue', 'wsocket_created', 'wsocket_closed', 'a10_socket_created', 'a10_socket_closed', 'No_a10_socket', 'No_other_side_socket', 'No_w_engine', 'No_w_socket', 'on_ld_timeout', 'idle_alarm', 'ack_alarm', 'close_alarm',
                    'delay_alarm', 'quic_malloc', 'quic_free', 'quic_malloc_failure', 'quick_malloc_failure', 'quic_lb', 'cid_zero', 'cid_cpu_hash', 'invalid_cid_sig', 'key_update_rx', 'key_update_tx'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'session_list': {
                'type': 'list',
                'fwd_source': {
                    'type': 'str',
                    },
                'fwd_source_cid': {
                    'type': 'str',
                    },
                'fwd_dest': {
                    'type': 'str',
                    },
                'fwd_dest_cid': {
                    'type': 'str',
                    },
                'fwd_state': {
                    'type': 'str',
                    },
                'fwd_flags': {
                    'type': 'str',
                    },
                'fwd_active_scids': {
                    'type': 'list',
                    'fwd_active_scid': {
                        'type': 'str',
                        }
                    },
                'fwd_available_scids': {
                    'type': 'list',
                    'fwd_available_scid': {
                        'type': 'str',
                        }
                    },
                'fwd_retired_scids': {
                    'type': 'list',
                    'fwd_retired_scid': {
                        'type': 'str',
                        }
                    },
                'fwd_active_dcids': {
                    'type': 'list',
                    'fwd_active_dcid': {
                        'type': 'str',
                        }
                    },
                'fwd_available_dcids': {
                    'type': 'list',
                    'fwd_available_dcid': {
                        'type': 'str',
                        }
                    },
                'fwd_retired_dcids': {
                    'type': 'list',
                    'fwd_retired_dcid': {
                        'type': 'str',
                        }
                    },
                'reverse_tuples': {
                    'type': 'list',
                    'rev_source': {
                        'type': 'str',
                        },
                    'rev_source_cid': {
                        'type': 'str',
                        },
                    'rev_dest': {
                        'type': 'str',
                        },
                    'rev_dest_cid': {
                        'type': 'str',
                        },
                    'rev_state': {
                        'type': 'str',
                        },
                    'rev_flags': {
                        'type': 'str',
                        },
                    'rev_active_scids': {
                        'type': 'list',
                        'rev_active_scid': {
                            'type': 'str',
                            }
                        },
                    'rev_available_scids': {
                        'type': 'list',
                        'rev_available_scid': {
                            'type': 'str',
                            }
                        },
                    'rev_retired_scids': {
                        'type': 'list',
                        'rev_retired_scid': {
                            'type': 'str',
                            }
                        },
                    'rev_active_dcids': {
                        'type': 'list',
                        'rev_active_dcid': {
                            'type': 'str',
                            }
                        },
                    'rev_available_dcids': {
                        'type': 'list',
                        'rev_available_dcid': {
                            'type': 'str',
                            }
                        },
                    'rev_retired_dcids': {
                        'type': 'list',
                        'rev_retired_dcid': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'total_sessions': {
                'type': 'int',
                }
            },
        'stats': {
            'type': 'dict',
            'client_conn_attempted': {
                'type': 'str',
                },
            'client_conn_handshake': {
                'type': 'str',
                },
            'client_conn_created': {
                'type': 'str',
                },
            'client_conn_local_closed': {
                'type': 'str',
                },
            'client_conn_remote_closed': {
                'type': 'str',
                },
            'client_conn_failed': {
                'type': 'str',
                },
            'server_conn_attempted': {
                'type': 'str',
                },
            'server_conn_handshake': {
                'type': 'str',
                },
            'server_conn_created': {
                'type': 'str',
                },
            'server_conn_local_closed': {
                'type': 'str',
                },
            'server_conn_remote_closed': {
                'type': 'str',
                },
            'server_conn_failed': {
                'type': 'str',
                },
            'q_conn_created': {
                'type': 'str',
                },
            'q_conn_freed': {
                'type': 'str',
                },
            'local_bi_stream_current': {
                'type': 'str',
                },
            'remote_bi_stream_current': {
                'type': 'str',
                },
            'local_bi_stream_created': {
                'type': 'str',
                },
            'remote_bi_stream_created': {
                'type': 'str',
                },
            'local_bi_stream_closed': {
                'type': 'str',
                },
            'remote_bi_stream_closed': {
                'type': 'str',
                },
            'local_uni_stream_current': {
                'type': 'str',
                },
            'remote_uni_stream_current': {
                'type': 'str',
                },
            'local_uni_stream_created': {
                'type': 'str',
                },
            'remote_uni_stream_created': {
                'type': 'str',
                },
            'local_uni_stream_closed': {
                'type': 'str',
                },
            'remote_uni_stream_closed': {
                'type': 'str',
                },
            'stream_error': {
                'type': 'str',
                },
            'stream_fail_to_insert': {
                'type': 'str',
                },
            'padding_frame_rx': {
                'type': 'str',
                },
            'padding_frame_tx': {
                'type': 'str',
                },
            'ping_frame_rx': {
                'type': 'str',
                },
            'ping_frame_tx': {
                'type': 'str',
                },
            'ack_frame_rx': {
                'type': 'str',
                },
            'ack_frame_tx': {
                'type': 'str',
                },
            'ack_ecn_frame_rx': {
                'type': 'str',
                },
            'ack_ecn_frame_tx': {
                'type': 'str',
                },
            'stream_rst_frame_rx': {
                'type': 'str',
                },
            'stream_rst_frame_tx': {
                'type': 'str',
                },
            'stream_stop_frame_rx': {
                'type': 'str',
                },
            'stream_stop_frame_tx': {
                'type': 'str',
                },
            'crypto_frame_rx': {
                'type': 'str',
                },
            'crypto_frame_tx': {
                'type': 'str',
                },
            'new_token_frame_rx': {
                'type': 'str',
                },
            'new_token_frame_tx': {
                'type': 'str',
                },
            'stream_frame_rx': {
                'type': 'str',
                },
            'stream_frame_tx': {
                'type': 'str',
                },
            'stream_09_frame_rx': {
                'type': 'str',
                },
            'stream_09_frame_tx': {
                'type': 'str',
                },
            'stream_0a_frame_rx': {
                'type': 'str',
                },
            'stream_0a_frame_tx': {
                'type': 'str',
                },
            'stream_0b_frame_rx': {
                'type': 'str',
                },
            'stream_0b_frame_tx': {
                'type': 'str',
                },
            'stream_0c_frame_rx': {
                'type': 'str',
                },
            'stream_0c_frame_tx': {
                'type': 'str',
                },
            'stream_0d_frame_rx': {
                'type': 'str',
                },
            'stream_0d_frame_tx': {
                'type': 'str',
                },
            'stream_0e_frame_rx': {
                'type': 'str',
                },
            'stream_0e_frame_tx': {
                'type': 'str',
                },
            'stream_0f_frame_rx': {
                'type': 'str',
                },
            'stream_0f_frame_tx': {
                'type': 'str',
                },
            'max_data_frame_rx': {
                'type': 'str',
                },
            'max_data_frame_tx': {
                'type': 'str',
                },
            'max_stream_data_frame_rx': {
                'type': 'str',
                },
            'max_stream_data_frame_tx': {
                'type': 'str',
                },
            'max_bi_stream_frame_rx': {
                'type': 'str',
                },
            'max_bi_stream_frame_tx': {
                'type': 'str',
                },
            'max_uni_stream_frame_rx': {
                'type': 'str',
                },
            'max_uni_stream_frame_tx': {
                'type': 'str',
                },
            'data_blocked_frame_rx': {
                'type': 'str',
                },
            'data_blocked_frame_tx': {
                'type': 'str',
                },
            'stream_data_blocked_frame_rx': {
                'type': 'str',
                },
            'stream_data_blocked_frame_tx': {
                'type': 'str',
                },
            'bi_stream_data_blocked_frame_rx': {
                'type': 'str',
                },
            'bi_stream_data_blocked_frame_tx': {
                'type': 'str',
                },
            'uni_stream_data_blocked_frame_rx': {
                'type': 'str',
                },
            'uni_stream_data_blocked_frame_tx': {
                'type': 'str',
                },
            'new_conn_id_frame_rx': {
                'type': 'str',
                },
            'new_conn_id_frame_tx': {
                'type': 'str',
                },
            'retire_conn_id_frame_rx': {
                'type': 'str',
                },
            'retire_conn_id_frame_tx': {
                'type': 'str',
                },
            'path_challenge_frame_rx': {
                'type': 'str',
                },
            'path_challenge_frame_tx': {
                'type': 'str',
                },
            'path_response_frame_rx': {
                'type': 'str',
                },
            'path_response_frame_tx': {
                'type': 'str',
                },
            'conn_close_frame_rx': {
                'type': 'str',
                },
            'conn_close_frame_tx': {
                'type': 'str',
                },
            'app_conn_close_frame_rx': {
                'type': 'str',
                },
            'app_conn_close_frame_tx': {
                'type': 'str',
                },
            'handshake_done_frame_rx': {
                'type': 'str',
                },
            'handshake_done_frame_tx': {
                'type': 'str',
                },
            'unknown_frame': {
                'type': 'str',
                },
            'stream_fin_receive': {
                'type': 'str',
                },
            'stream_fin_up': {
                'type': 'str',
                },
            'stream_fin_down': {
                'type': 'str',
                },
            'stream_fin_send': {
                'type': 'str',
                },
            'stream_congest': {
                'type': 'str',
                },
            'stream_open': {
                'type': 'str',
                },
            'stream_pause_data': {
                'type': 'str',
                },
            'stream_resume_data': {
                'type': 'str',
                },
            'stream_not_send': {
                'type': 'str',
                },
            'stream_stop_send': {
                'type': 'str',
                },
            'stream_created': {
                'type': 'str',
                },
            'stream_freed': {
                'type': 'str',
                },
            'INITIAL_rx': {
                'type': 'str',
                },
            'INITIAL_tx': {
                'type': 'str',
                },
            'RTT_0_rx': {
                'type': 'str',
                },
            'RTT_0_tx': {
                'type': 'str',
                },
            'HANDSHAKE_rx': {
                'type': 'str',
                },
            'HANDSHAKE_tx': {
                'type': 'str',
                },
            'RETRY_rx': {
                'type': 'str',
                },
            'RETRY_tx': {
                'type': 'str',
                },
            'VER_rx': {
                'type': 'str',
                },
            'VER_tx': {
                'type': 'str',
                },
            'RTT_updated': {
                'type': 'str',
                },
            'Needs_ack': {
                'type': 'str',
                },
            'Delayed_ack': {
                'type': 'str',
                },
            'Packet_rx': {
                'type': 'str',
                },
            'Packet_tx': {
                'type': 'str',
                },
            'Packet_tx_failed': {
                'type': 'str',
                },
            'Congest_wnd_inc': {
                'type': 'str',
                },
            'Congest_wnd_dec': {
                'type': 'str',
                },
            'No_congest_wnd': {
                'type': 'str',
                },
            'Burst_limited': {
                'type': 'str',
                },
            'Packet_loop_limited': {
                'type': 'str',
                },
            'Receive_wnd_limited': {
                'type': 'str',
                },
            'Parse_error': {
                'type': 'str',
                },
            'Error_close': {
                'type': 'str',
                },
            'Unknown_scid': {
                'type': 'str',
                },
            'Dcid_mismatch': {
                'type': 'str',
                },
            'Packet_too_short': {
                'type': 'str',
                },
            'Invalid_version': {
                'type': 'str',
                },
            'Invalid_Packet': {
                'type': 'str',
                },
            'Invalid_conn_match': {
                'type': 'str',
                },
            'Invalid_session_packet': {
                'type': 'str',
                },
            'Stateless_reset': {
                'type': 'str',
                },
            'Packet_lost': {
                'type': 'str',
                },
            'Packet_drop': {
                'type': 'str',
                },
            'Packet_retransmit': {
                'type': 'str',
                },
            'Packet_out_of_order': {
                'type': 'str',
                },
            'Quic_packet_drop': {
                'type': 'str',
                },
            'Encode_error': {
                'type': 'str',
                },
            'Decode_failed': {
                'type': 'str',
                },
            'Decode_stream_error': {
                'type': 'str',
                },
            'Exceed_flow_control': {
                'type': 'str',
                },
            'Crypto_stream_not_found': {
                'type': 'str',
                },
            'Exceed_max_stream_id': {
                'type': 'str',
                },
            'Stream_id_mismatch': {
                'type': 'str',
                },
            'Ack_delay_huge': {
                'type': 'str',
                },
            'Ack_rng_huge_1': {
                'type': 'str',
                },
            'Ack_rng_huge_2': {
                'type': 'str',
                },
            'Ack_rng_huge_3': {
                'type': 'str',
                },
            'Too_noisy_fuzzing': {
                'type': 'str',
                },
            'Max_stream_too_big': {
                'type': 'str',
                },
            'Stream_blocked': {
                'type': 'str',
                },
            'New_conn_id_len_zero': {
                'type': 'str',
                },
            'New_conn_id_len_non_zero': {
                'type': 'str',
                },
            'Illegal_stream_len': {
                'type': 'str',
                },
            'Illegal_reason_len': {
                'type': 'str',
                },
            'Illegal_seq': {
                'type': 'str',
                },
            'Illegal_rpt': {
                'type': 'str',
                },
            'Illegal_len': {
                'type': 'str',
                },
            'Illegal_token_len': {
                'type': 'str',
                },
            'Cannot_insert_cid': {
                'type': 'str',
                },
            'Cannot_insert_srt': {
                'type': 'str',
                },
            'Cannot_retire_cid': {
                'type': 'str',
                },
            'No_next_scid': {
                'type': 'str',
                },
            'Token_len_too_long': {
                'type': 'str',
                },
            'Server_receive_new_token': {
                'type': 'str',
                },
            'Zero_frame_packet': {
                'type': 'str',
                },
            'Err_frame_dec1': {
                'type': 'str',
                },
            'Err_frame_dec': {
                'type': 'str',
                },
            'Err_frame_decb': {
                'type': 'str',
                },
            'Err_frame_final_size': {
                'type': 'str',
                },
            'Err_flow_control': {
                'type': 'str',
                },
            'Err_protocol_violation': {
                'type': 'str',
                },
            'Server_rx_handshake_done': {
                'type': 'str',
                },
            'Pkt_acked_failed': {
                'type': 'str',
                },
            'Pn_insert_failed': {
                'type': 'str',
                },
            'Pn_delete_failed': {
                'type': 'str',
                },
            'Acked_packet_freed': {
                'type': 'str',
                },
            'Tx_buffer_enq': {
                'type': 'str',
                },
            'Tx_buffer_deq': {
                'type': 'str',
                },
            'App_buffer_enq': {
                'type': 'str',
                },
            'App_buffer_deq': {
                'type': 'str',
                },
            'App_buffer_queue_full': {
                'type': 'str',
                },
            'Iov_buffer_bind': {
                'type': 'str',
                },
            'Iov_buffer_unbind': {
                'type': 'str',
                },
            'Iov_buffer_dup': {
                'type': 'str',
                },
            'Iov_alloc_len': {
                'type': 'str',
                },
            'Iov_IO': {
                'type': 'str',
                },
            'Iov_System': {
                'type': 'str',
                },
            'No_tx_queue': {
                'type': 'str',
                },
            'wsocket_created': {
                'type': 'str',
                },
            'wsocket_closed': {
                'type': 'str',
                },
            'a10_socket_created': {
                'type': 'str',
                },
            'a10_socket_closed': {
                'type': 'str',
                },
            'No_a10_socket': {
                'type': 'str',
                },
            'No_other_side_socket': {
                'type': 'str',
                },
            'No_w_engine': {
                'type': 'str',
                },
            'No_w_socket': {
                'type': 'str',
                },
            'on_ld_timeout': {
                'type': 'str',
                },
            'idle_alarm': {
                'type': 'str',
                },
            'ack_alarm': {
                'type': 'str',
                },
            'close_alarm': {
                'type': 'str',
                },
            'delay_alarm': {
                'type': 'str',
                },
            'quic_malloc': {
                'type': 'str',
                },
            'quic_free': {
                'type': 'str',
                },
            'quic_malloc_failure': {
                'type': 'str',
                },
            'quick_malloc_failure': {
                'type': 'str',
                },
            'quic_lb': {
                'type': 'str',
                },
            'cid_zero': {
                'type': 'str',
                },
            'cid_cpu_hash': {
                'type': 'str',
                },
            'invalid_cid_sig': {
                'type': 'str',
                },
            'key_update_rx': {
                'type': 'str',
                },
            'key_update_tx': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/quic"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/quic"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["quic"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["quic"].get(k) != v:
            change_results["changed"] = True
            config_changes["quic"][k] = v

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
    payload = utils.build_json("quic", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

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
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["quic"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["quic-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["quic"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["quic"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
