"""Glossary of `debug dataplane pow performance` counters.

Built from the Palo Alto KB "How to interpret output of debug dataplane pow
performance..." (KB), LIVEcommunity threads (LC) and name-based inference.

Confidence: D = documented by Palo Alto source, G = category documented by KB but
meaning inferred from name, I = inferred from name only (hypothesis), U = unknown.
"""

GLOSSARY = {}      # name -> dict(kind, category, conf, meaning)
CATEGORY_ORDER = []


def _add(kind, category, conf, names, meaning, per_name=None):
    if category not in CATEGORY_ORDER:
        CATEGORY_ORDER.append(category)
    for n in names.split():
        m = (per_name or {}).get(n, meaning)
        GLOSSARY[n] = dict(kind=kind, category=category, conf=conf, meaning=m)


# ---------------------------------------------------------------- fields
FIELDS = {
    'count': 'Times the group/function was scheduled in the current window (D).',
    'avg-us': 'Average processing time per invocation, microseconds (D).',
    'max-us': 'Maximum single processing time, microseconds (D).',
    'total-us': 'avg-us x count: total time spent in the window (9.1+) (D).',
    'ac-count': 'Accumulated count since the last dataplane restart/reboot (D).',
    'ac-max-us': 'Maximum time accumulated since the last dataplane restart/reboot (D).',
    'ac-avg-us': 'Average time accumulated since the last dataplane restart/reboot (D).',
    'ac-total-us': 'Not defined by Palo Alto; most likely ac-avg-us x ac-count (I).',
    'avg-ticks': 'Average processing time of the bucket in CPU ticks (histogram section; not documented) (I).',
    'col': 'Histogram bucket index; grows roughly with log2 of the time (not documented) (I).',
}

# ---------------------------------------------------------------- groups
G = 'Work group'
_add('group', G, 'D', 'flow_lookup', 'Lookup of an existing session/flow for the packet.')
_add('group', G, 'D', 'flow_fastpath', 'Fast-path processing; also covers post-slowpath processing and content inspection, so most L7 work shows up here.')
_add('group', G, 'D', 'flow_slowpath', 'Slow path: route and policy lookup, session setup.')
_add('group', G, 'D', 'flow_forwarding', 'Forwarding stage of the packet.')
_add('group', G, 'D', 'flow_mgmt', 'Installation and clearing of the session table.')
_add('group', G, 'D', 'flow_ctrl', 'Session aging and handling of net-messages.')
_add('group', G, 'D', 'nac_result', 'Analysis of the result of signature-match output.')
_add('group', G, 'D', 'flow_np', 'Network-processor stage: the very first program packets enter.')
_add('group', G, 'D', 'dfa_result', 'DFA pattern-match processing (a third-party blog reads it as App-ID signature matching).')
_add('group', G, 'D', 'module_internal', 'Control messages between internal components (the mi_* and module_internal_* functions).')
_add('group', G, 'D', 'aho_result', 'Pattern-match processing; KB wording duplicates dfa_result. A third-party blog reads it as threat-signature matching (Aho-Corasick).')
_add('group', G, 'D', 'zip_result', 'ZIP processing.')
_add('group', G, 'D', 'pktlog_forwarding', 'Forwarding of logs to the management plane.')
_add('group', G, 'D', 'flow_host', 'Processing of packets destined to the firewall itself.')
_add('group', G, 'I', 'send_out', 'Not documented. By name: transmit of packets out of the firewall.')
_add('group', G, 'I', 'send_host', 'Not documented. By name: transmit of packets to the host/management path.')
_add('group', G, 'U', 'lwm', 'Not documented; acronym unknown. Absent on some platforms.')

# ------------------------------------------------------------ L7 functions
C = 'Layer-7 / pattern matching'
for n, m in dict(
    dfa_match='DFA pattern-match call.', fpga_dfa='DFA match offloaded to FPGA (hardware platforms only).',
    fpga_aho='Aho-Corasick match offloaded to FPGA.', hs_match='Hyperscan-style pattern match.',
    hs_ctxt_free_match='Hyperscan-style match in context-free (stateless) mode.',
    regex_lookup='Regular-expression lookup stage.', regex_postfpga='Regex processing after the FPGA stage.',
    reg_expr_match='Regular-expression match.', appid_match='Application-signature match.',
    appid_result='Handling of the App-ID result.',
    get_gid='Obtains a group/signature ID (exact meaning unknown).',
    detector_run_p1='Application detector/decoder, phase 1.', detector_run_p2='Application detector/decoder, phase 2.',
    mi_aho_sw_offload='Probably the software fallback of Aho-Corasick matching (community inference).',
).items():
    _add('func', C, 'I' if n == 'mi_aho_sw_offload' else 'G', n, m)

C = 'Layer-7 / Content-ID and ML'
_add('func', C, 'D', 'ctd_token', 'Content-decoder token processing: where a large part of L7 inspection runs. Its time tracks pkt_recv and ctd_pkt_slowpath (more traffic = more inspection).')
_add('func', C, 'D', 'sml_vm', 'Content-decoder virtual machine; same role as ctd_token, normally at the top of the ranking when most traffic is inspected.')
for n, m in dict(
    cad_threatsig_match='Threat-signature match ("cad" unexpanded).', cad_appsig_match='Application-signature match ("cad" unexpanded).',
    raven_match='Match in the "raven" engine (internal name, purpose unknown).', raven_match_header='Raven match on headers.',
    raven_match_body='Raven match on body.', raven_sig_get_action='Retrieves the action for a Raven signature hit.',
    ctd_pw_check='Password-related check (credential detection).', ctd_pw_md4='MD4 hashing used by the password check.',
    ctd_pw_extract='Password/credential extraction.', mlav_cache_lookup='Inline ML antivirus: cache lookup.',
    mlav_xgb_model_classify='Inline ML antivirus: XGBoost-style model classification.',
    mlav_lr_model_classify='Inline ML antivirus: logistic-regression model classification.',
    detector_alloc_athreat='Allocation for an advanced-threat detector.',
).items():
    _add('func', C, 'I' if n == 'detector_alloc_athreat' else 'G', n, m)

C = 'Layer-7 / protocol handling'
for n, m in dict(
    http2_proc_recv='HTTP/2 processing, receive direction.', http2_proc_send='HTTP/2 processing, send direction.',
    prl_rewrite='Packet rewrite ("prl" unexpanded).', pkt_rewrite='Packet rewrite.', zip_deflate='Deflate (de)compression.',
).items():
    _add('func', C, 'G', n, m)
_add('func', C, 'I', 'brotli_deflate', 'Brotli decompression.')

# -------------------------------------------------------------- decryption
C = 'Decryption / crypto'
for n, m in dict(
    ssl_proxy_proc='Overall SSL forward-proxy processing; overlaps with the crypto functions below.',
    ssl_encode='TLS record encoding.', cipher_enc='Bulk symmetric encryption.',
    bn_mod_exp='Big-number modular exponentiation (RSA/DH primitive).',
    rsa_operation_pub_enc='RSA public-key encrypt.', rsa_operation_pub_dec='RSA public-key decrypt.',
    rsa_operation_priv_enc='RSA private-key encrypt.', rsa_operation_priv_dec='RSA private-key decrypt.',
    rsa_key_gen='RSA key-pair generation.', rsa_sign_sw='RSA sign, software.', rsa_verify_sw='RSA verify, software.',
    rsa_sign_hw='RSA sign, hardware accelerator.', rsa_verify_hw='RSA verify, hardware accelerator.',
    rsa_sign_hw_latency='Latency of hardware RSA sign (latency, not CPU time).',
    rsa_verify_hw_latency='Latency of hardware RSA verify (latency, not CPU time).',
    eckey_dup='Duplication of an EC key object.',
    ecdhe_key_gen='ECDHE ephemeral key generation.', ecdhe_key_gen_mul='ECDHE key generation, multiply step.',
    ecdhe_key_gen_sw='ECDHE key generation, software.', ecdhe_key_gen_hw='ECDHE key generation, hardware.',
    ecdhe_key_gen_hw_latency='Latency of hardware ECDHE key generation (latency, not CPU time).',
    ecdhe_key_compute='ECDHE shared-secret computation.', ecdhe_key_compute_mul='ECDHE secret computation, multiply step.',
    ecdhe_key_compute_sw='ECDHE secret computation, software.', ecdhe_key_compute_hw='ECDHE secret computation, hardware.',
    ecdhe_key_compute_hw_latency='Latency of hardware ECDHE secret computation (latency, not CPU time).',
    ecdhe_generate_xchg_key='Generation of the exchange key.',
    ecdhe_gen_key_exchange_msg='Building the key-exchange message.', ecdhe_get_key_exchange_msg='Retrieving the key-exchange message.',
    ecdhe_parse_server_key_exchange_msg='Parsing the ServerKeyExchange message.',
    ecdhe_gen_server_key_exchange_msg='Generating the ServerKeyExchange message.',
    dhe_gen_para='Classic DHE parameter generation.', dhe_gen_key='Classic DHE key generation.',
    dhe_key_compute='Classic DHE secret computation.',
    ecdsa_sign_sw='ECDSA sign, software.', ecdsa_verify_sw='ECDSA verify, software.',
    ecdsa_sign_hw='ECDSA sign, hardware.', ecdsa_verify_hw='ECDSA verify, hardware.',
    ecdsa_sign_hw_latency='Latency of hardware ECDSA sign (latency, not CPU time).',
    ecdsa_verify_hw_latency='Latency of hardware ECDSA verify (latency, not CPU time).',
    poll_delay_qat='Intel QAT crypto accelerator: polling delay.', qat_packet_latency='QAT per-packet latency (latency, not CPU time).',
    qat_batch_latency='QAT batch latency (latency, not CPU time).',
    rsa_RSA_sign='Library-level RSA sign (likely variant of rsa_sign_*).', rsa_RSA_verify='Library-level RSA verify (likely variant of rsa_verify_*).',
).items():
    _add('func', C, 'I' if n.startswith('rsa_RSA') else 'G', n, m)

# ------------------------------------------------------------ tunnel / VPN
C = 'Tunnel / VPN'
for n, m in dict(
    tunnel_encap='Tunnel encapsulation.', tunnel_decap='Tunnel decapsulation.', tunnel_esp='IPsec ESP processing.',
    tunnel_esp_decap='IPsec ESP decapsulation.', tunnel_ah='IPsec AH processing.', tunnel_ah_decap='IPsec AH decapsulation.',
    tunnel_fwd='Forwarding of tunnelled packets.', tunnel_prepare='Pre-processing around tunnel handling.',
    tunnel_post='Post-processing around tunnel handling.', vpn_send_to_client='Sending packets to a GlobalProtect/VPN client.',
    vpn_cookie_response='VPN cookie response (anti-DoS cookie exchange, inferred).',
).items():
    _add('func', C, 'G', n, m)

# ---------------------------------------------------------- URL filtering
C = 'URL filtering'
for n, m in dict(
    urlcache_lookup='Lookup in the URL-category cache.', urlcache_insert='Insert into the URL-category cache.',
    urlcache_delete='Delete from the URL-category cache.', urlcache_update='Update of URL-cache entries.',
    urlcache_lru='LRU eviction of the URL-category cache.',
).items():
    _add('func', C, 'G', n, m)

# ---------------------------------------------------- policy / sessions etc.
_add('func', 'Policy / identity', 'I', 'policy_lookup', 'Security policy lookup (slow path).')
_add('func', 'Policy / identity', 'I', 'user_group_policy', 'Policy evaluation involving User-ID groups.')
_add('func', 'Policy / identity', 'I', 'userid_cache_lookup', 'User-ID cache lookup.')
_add('func', 'Session lifecycle', 'I', 'session_install', 'Installing a session in the table.')
_add('func', 'Session lifecycle', 'I', 'session_age', 'Aging of sessions.')
_add('func', 'Session lifecycle', 'I', 'session_ager', 'Session ager task (likely same as session_age).')
_add('func', 'Session lifecycle', 'I', 'session_delete', 'Deleting a session.')
_add('func', 'Session lifecycle', 'I', 'session_purge', 'Purging sessions.')
_add('func', 'Session lifecycle', 'I', 'session_ager_scan', 'Ager scan over the session table (detail of session_ager).')
_add('func', 'Session lifecycle', 'I', 'session_local_pool_flush', 'Flush of the per-core session pool.')
_add('func', 'Session lifecycle', 'I', 'session_local_pool_refill', 'Refill of the per-core session pool.')
_add('func', 'Session lifecycle', 'I',
     'session_delete_age_n_sessions session_delete_bind_q session_delete_l4_resource_free session_delete_l7_ctd_fini '
     'session_delete_l7_file_fini session_delete_l7_url_free session_delete_mutex session_delete_predict_lock '
     'session_delete_predict_session session_delete_resource_free session_delete_tcp_free '
     'sess_del_predict_resource_free sess_del_resource_free_inner',
     'Step of session teardown (resource release, content-inspection/URL cleanup, locking).')
_add('func', 'Table aging', 'I', 'age_arp', 'Aging of ARP entries.')
_add('func', 'Table aging', 'I', 'age_pbf_ret_mac', 'Aging of PBF return-MAC entries.')
_add('func', 'Table aging', 'I', 'age_mfib', 'Aging of multicast FIB entries.')
_add('func', 'Logging', 'I', 'pktlog_log', 'Creating packet/traffic log records.')
_add('func', 'Logging', 'I', 'pktlog_send', 'Sending log records to the management plane.')
_add('func', 'DoS protection', 'I', 'dos_update', 'Update of DoS/protection counters or tables.')

# -------------------------------------------------- latency (not CPU time)
C = 'Latency measures (not CPU time)'
_add('func', C, 'I', 'pkt_rx_tx_latency', 'Packet receive-to-transmit latency. Average ~500 us over billions of samples: a latency metric, exclude from CPU rankings.')
_add('func', C, 'I', 'pbp_buf_latency', 'Buffer latency tied to Packet Buffer Protection. A latency metric, exclude from CPU rankings.')

# ------------------------------------------------------- module internal
C = 'Module internal: SSL/TLS proxy messages'
_add('func', C, 'I',
     'mi_proxy mi_proxy_circuit_internal mi_proxy_host_close mi_proxy_host_open mi_proxy_host_rcv_data mi_proxy_host_rcv_pkt '
     'mi_proxy_host_xmt_data mi_proxy_hsm_response mi_proxy_offload_packet mi_proxy_offload_session_notify '
     'mi_proxy_offload_site_setup mi_proxy_queue_update mi_proxy_revert_packet mi_proxy_revert_session_notify '
     'mi_proxy_revert_session_setup mi_proxy_ssl_sess_cache mi_proxy_sslvpn_ck_cache mi_proxy_timer_advance '
     'mi_proxy_timer_expire mi_proxy_tunnel',
     'Message handled by the proxy engine inside module_internal (host connections/data, timers, HSM, offload/revert, SSL session cache).')
C = 'Module internal: responses from services'
_add('func', C, 'I',
     'mi_cloud_dns_response mi_host_response mi_response_doh_timeout mi_response_kcd mi_response_mlav mi_response_mlav_timeout '
     'mi_response_swg_timeout mi_response_url_ctd mi_response_url_ssl mi_response_url_timeout mi_response_wfrt mi_response_wfrt_timeout',
     'Handling of an answer from another component or cloud service (URL category, WildFire real-time, inline ML, DNS/DoH, SWG, host); _timeout = the wait expired.')
C = 'Module internal: HA / HTTP2 / SSL-VPN'
_add('func', C, 'I', 'mi_ha_session_message mi_ha_session_teardown mi_http2_frame_ingress mi_sslvpn_start_tunnel mi_sslvpn_stop_tunnel',
     'HA session sync/teardown message, HTTP/2 frame, or SSL-VPN tunnel start/stop handled in module_internal.')
C = 'Module internal: control messages'
_add('func', C, 'I',
     'mi_cluster mi_fec_reinject mi_flow mi_inter_dp mi_mfib_update mi_mfib_update_flush mi_mfib_update_notify '
     'mi_post_dfa_sw_offload mi_scan_invoked_fpga mi_scan_invoked_swbuf mi_sesscache module_internal_bind_ack '
     'module_internal_bind_nack module_internal_ev_update module_internal_flow_stats module_internal_gtp_bind_nack '
     'module_internal_gtpu_bind_ack module_internal_gtpu_bind_nack module_internal_notify_session_bind '
     'module_internal_owner_new_pp module_internal_owner_predict module_internal_owner_unknown_ack module_internal_predict_ack',
     'Internal control message (cluster, inter-DP, multicast FIB, session binding/ownership/prediction), as the KB describes the module_internal group.')

# ------------------------------------------------------ feature families
_add('func', 'Mobile core (GTP/SCTP/PFCP/5G)', 'I',
     'gtp_gc mi_gtp_c_install mi_gtp_general mi_gtp_inter_dp mi_gtp_process_frm_ctd mi_gtp_reinject mi_http2_5gc_reinject '
     'mi_pfcp_process_frm_ctd mi_ueip_cluster module_ueip_ager_lock module_ueip_bulk_proc module_ueip_delete module_ueip_insert '
     'module_ueip_modify module_ueip_refresh module_ueip_thash_ager_lock sctp_cookie_echo_update sctp_ss_update',
     'Handling of GTP, SCTP, PFCP or 5G service-based traffic and the UE-IP table. Zero when these features are unused.')
_add('func', 'SD-WAN / FEC', 'I', 'sdwan_fec_res_get sdwan_fec_res_unget sdwan_geneve_decap_only sdwan_geneve_encap_only sdwan_path_selection flow_fec_decode flow_fec_encode',
     'SD-WAN path selection, Geneve encapsulation or forward error correction.')
_add('func', 'Session offload', 'I', 'offload_add offload_close offload_del offload_get', 'Management of session-offload entries.')
_add('func', 'Inline ML', 'I', 'ldl_mlc2_http ldl_mlc2_http_char_load ldl_mlc2_http_model_load ldl_mlc2_http_ort_load ldl_mlc2_http_word_load',
     'Loading of models/data for an inline ML HTTP analyzer ("ldl", "mlc2" unexpanded).')
C = 'Miscellaneous'
for n, m in dict(
    app_diag='Application diagnostics (by name).', devid_sampling='Device-ID sampling (by name).',
    memseg_alloc='Memory segment allocation.', memseg_free='Memory segment free.',
    netdec_proc_eval='Network decoder evaluation (by name).', netinsp_proc_packet='Network inspection packet processing (by name).',
    receive_pkt='Packet receive (by name).', tim_check='Timer check.',
).items():
    _add('func', C, 'I', n, m)
_add('func', 'Unresolved', 'U', 'stack_trace', 'Not documented; probably a diagnostic hook. Unknown.')
_add('func', 'Unresolved', 'U', 'inline_switch', 'Not documented; unknown (inline-mode switching?).')

CONF_TEXT = {
    'D': 'Documented by a Palo Alto source.',
    'G': 'Category documented by the Palo Alto KB; meaning inferred from the name.',
    'I': 'Inferred from the name only; treat as a hypothesis.',
    'U': 'Unknown: no meaning found.',
}

# Families for names not in GLOSSARY (checked in this order, by prefix).
PREFIX_FALLBACK = [
    ('mi_proxy', 'Module internal: SSL/TLS proxy messages'),
    ('mi_response', 'Module internal: responses from services'),
    ('mi_', 'Module internal: control messages'),
    ('module_internal', 'Module internal: control messages'),
    ('module_ueip', 'Mobile core (GTP/SCTP/PFCP/5G)'), ('gtp_', 'Mobile core (GTP/SCTP/PFCP/5G)'),
    ('sctp_', 'Mobile core (GTP/SCTP/PFCP/5G)'), ('sdwan_', 'SD-WAN / FEC'), ('offload_', 'Session offload'),
    ('session_', 'Session lifecycle'), ('sess_del', 'Session lifecycle'), ('ldl_', 'Inline ML'),
    ('tunnel_', 'Tunnel / VPN'), ('urlcache_', 'URL filtering'),
    ('rsa_', 'Decryption / crypto'), ('ecdhe_', 'Decryption / crypto'), ('ecdsa_', 'Decryption / crypto'),
]


def lookup(name):
    """Return dict(kind, category, conf, meaning) for any counter name (never raises)."""
    if name in GLOSSARY:
        return GLOSSARY[name]
    for p, cat in PREFIX_FALLBACK:
        if name.startswith(p):
            return dict(kind='func', category=cat, conf='I',
                        meaning='Not in the glossary; classified by name prefix only.')
    return dict(kind='func', category='Unclassified', conf='U', meaning='Not in the glossary. No meaning known.')


# ---------------------------------------------------------------- report helpers
LATENCY_CATEGORY = 'Latency measures (not CPU time)'

# Column/field descriptions of the report that are not raw pow columns.
EXTRA_FIELDS = {
    'name': 'Counter name as printed by `debug dataplane pow performance all`. Hover a name for its glossary entry. (D)',
    'category': 'Family assigned by the coarse name rules of the toolbox (L7, DECRYPT, TUNNEL, URL, other, latency). (I)',
    'gcategory': 'Glossary family of the counter (partly inferred, see the confidence code). (I)',
    'conf': 'Confidence of the glossary entry: D documented, G category documented, I inferred from the name, U unknown. (D)',
    'share': 'Share of the CPU-time total of the table (window total-us); latency counters are left out. Functions overlap, so shares are indicative. (I)',
    'ac-share': 'Share of the accumulated CPU-time total (ac-total-us); latency counters are left out. (I)',
    'ratio': 'count / ac-count: the part of the accumulated calls that fall in the current window. A high value means the row is busy now compared with its history. (D)',
    'flags': 'Badges raised by the heuristics (see the flag reference in the help). (D)',
    'funcs': 'Number of counters of this family present in the output. (D)',
    'active': 'Counters of this family with a non-zero window count or total-us. (D)',
    'p50': 'Approximate median of the histogram (average time of the bin where the cumulative count reaches 50%). (I)',
    'p99': 'Approximate 99th percentile of the histogram, same method as the median. (I)',
    'buckets': 'Number of histogram bins with data. (D)',
}


def field_entries():
    """Column descriptions as {key: {'m': text, 'f': confidence}} for the report tooltips."""
    import re
    out = {}
    for k, text in list(FIELDS.items()) + list(EXTRA_FIELDS.items()):
        m = re.search(r'\s*\(([DGIU])\)\.?\s*$', text)
        out[k] = {'m': text[:m.start()] if m else text, 'f': m.group(1) if m else 'D'}
    return out


def glossary_subset(names):
    """Glossary entries of the given counter names, ready for the report JSON."""
    out = {}
    for n in sorted(set(names)):
        g = lookup(n)
        out[n] = {'c': g['category'], 'f': g['conf'], 'm': g['meaning'], 'k': g['kind'],
                  'u': 1 if n in GLOSSARY else 0}
    return out
