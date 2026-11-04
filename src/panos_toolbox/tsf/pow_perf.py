"""Parser and anomaly heuristics for the output of ``debug dataplane pow performance``.

The command prints, for each dataplane workgroup ("group") and function ("func"),
how often it was scheduled and how long it took, both for the current window and
accumulated since the last DP restart. Per-core variants (``... all core A-B``) and
histograms of the processing time per call are printed too.

Pre-9.1 releases print only ``max-us avg-us count``; 9.1 and later add ``total-us``
and the accumulated ``ac-*`` columns.

The heuristics follow the Palo Alto Networks KB article "How to interpret output of
debug dataplane pow performance during troubleshooting high DP CPU". They are hints
for the investigation, not verdicts. Tune POW_THRESHOLDS to the environment.

Standard library only. No HTML in this module.
"""
import copy
import re
import statistics

from . import pow_glossary

# Every number used by evaluate(). Override any of them with
# evaluate(parsed, thresholds={'key': value}); unknown keys raise ValueError.
POW_THRESHOLDS = {
    # Top-N rows by total-us (current window and accumulated) are checked for CPU share.
    'top_n': 5,
    'share_warn': 10.0,             # percent of the table total-us (warn)
    'share_crit': 30.0,             # percent of the table total-us (crit)
    # Single-call spike: max-us high compared with the average.
    'max_spike_abs_us': 10000,      # max-us must reach this value
    'max_spike_ratio': 50.0,        # and max-us / avg-us must reach this ratio
    'max_spike_crit_us': 100000,    # crit instead of warn at this max-us
    # Minimum number of calls before averages and ratios are trusted.
    'min_count': 10,
    # Current average compared with the since-boot average (traffic pattern change).
    'drift_ratio': 2.0,             # warn
    'drift_crit_ratio': 5.0,        # crit
    'drift_min_avg_us': 5.0,        # ignore drift below this average (noise)
    # Slow average per call. DECRYPT functions are slow by nature, hence a higher limit.
    'high_avg_us': 1000,
    'high_avg_us_decrypt': 10000,
    # A category holding at least this percent of function CPU time is listed as dominant.
    'category_dominance': 50.0,
    # A core is imbalanced when its workgroup total-us reaches this multiple of the
    # median of the active cores (crit at twice this multiple).
    'core_imbalance_ratio': 2.0,
    'min_active_cores': 3,
    # Histogram tail: bins with avg-us >= hist_tail_us that hold less than
    # hist_tail_share percent of the calls (crit when avg-us >= hist_tail_crit_us).
    'hist_tail_us': 10000,
    'hist_tail_crit_us': 100000,
    'hist_tail_share': 1.0,
    # Latency counters (not CPU time): flag when the window avg-us reaches this value.
    'latency_high_us': 1000,
    # Decryption/crypto holding at least this percent of function CPU time is reported
    # with a hint even below category_dominance.
    'decrypt_share_warn': 15.0,
    # Histogram: bins with avg-us >= hist_slow_us that hold at least hist_slow_share
    # percent of the histogram time, over at least hist_slow_min_count calls.
    'hist_slow_us': 1000,
    'hist_slow_share': 5.0,
    'hist_slow_min_count': 10,
}

def _names(text):
    return frozenset(text.split())


L7_FUNCS = _names("""
dfa_match appid_match get_gid regex_lookup regex_postfpga reg_expr_match sml_vm
detector_run_p1 detector_run_p2 appid_result ctd_token cad_threatsig_match cad_appsig_match
mlav_cache_lookup mlav_xgb_model_classify mlav_lr_model_classify http2_proc_recv
http2_proc_send hs_match hs_ctxt_free_match fpga_aho fpga_dfa ctd_pw_check ctd_pw_md4
ctd_pw_extract prl_rewrite pkt_rewrite raven_match raven_match_header raven_match_body
raven_sig_get_action zip_deflate
""")

DECRYPT_FUNCS = _names("""
ssl_proxy_proc ssl_encode rsa_operation_pub_enc rsa_operation_pub_dec rsa_operation_priv_enc
rsa_operation_priv_dec rsa_key_gen eckey_dup ecdhe_key_gen ecdhe_key_gen_mul
ecdhe_key_compute_mul ecdhe_key_compute ecdhe_generate_xchg_key ecdhe_gen_key_exchange_msg
ecdhe_get_key_exchange_msg ecdhe_parse_server_key_exchange_msg ecdhe_gen_server_key_exchange_msg
dhe_gen_para dhe_gen_key dhe_key_compute bn_mod_exp cipher_enc rsa_verify_sw rsa_sign_sw
poll_delay_qat qat_packet_latency qat_batch_latency ecdsa_verify_sw ecdsa_sign_sw
ecdhe_key_gen_sw ecdhe_key_compute_sw rsa_verify_hw rsa_sign_hw ecdsa_verify_hw ecdsa_sign_hw
ecdhe_key_gen_hw ecdhe_key_compute_hw rsa_verify_hw_latency rsa_sign_hw_latency
ecdsa_verify_hw_latency ecdsa_sign_hw_latency ecdhe_key_gen_hw_latency
ecdhe_key_compute_hw_latency
""")
DECRYPT_PREFIXES = ('rsa_', 'ecdhe_', 'ecdsa_', 'dhe_')

TUNNEL_FUNCS = _names("""
tunnel_encap tunnel_decap tunnel_esp tunnel_esp_decap tunnel_ah_decap tunnel_ah tunnel_fwd
tunnel_prepare tunnel_post vpn_send_to_client vpn_cookie_response
""")

URL_FUNCS = _names("""
urlcache_update urlcache_lookup urlcache_insert urlcache_delete urlcache_lru
""")

WORKGROUP_DESCRIPTIONS = {
    'flow_np': 'Network Processor, first program packets enter',
    'flow_lookup': 'existing session/flow lookup',
    'flow_mgmt': 'session table install/clear',
    'flow_fastpath': 'fastpath processing (incl. post-slowpath and content inspection)',
    'flow_slowpath': 'slow path (route+policy lookup, session setup)',
    'flow_forwarding': 'forwarding stage',
    'dfa_result': 'DFA pattern match processing',
    'aho_result': 'DFA pattern match processing',
    'module_internal': 'control messages between internal components',
    'zip_result': 'ZIP processing',
    'pktlog_forwarding': 'forwarding logs to MP',
    'flow_host': 'packets destined to the firewall',
    'flow_ctrl': 'aging sessions, net-messages',
    'nac_result': 'signature match result analysis',
}

_CMD_GLOBAL = ('debug dataplane pow performance all', 'debug dataplane pow performance')
_CMD_CORES_RE = re.compile(r'^debug dataplane pow performance all core (\d+)-(\d+)$')
_CLOCK_RE = re.compile(r'^[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \S+ \d{4}$')
_CORE_RE = re.compile(r'^Core (\d+):$')
_TABLE_RE = re.compile(r'^(group|func)\s')
# CLI prompt, e.g. 'admin@PA-560(active)> debug dataplane pow performance all'.
_PROMPT_RE = re.compile(r'^\S+@\S+?(?:\([^)]*\))?[>#]\s*(.*)$')
# 'DP dp0:', 'target-dp: *.dp0' or a bare 'dp0:' header of a multi-dataplane output.
_DP_RE = re.compile(r'^(?:(?:DP|target-dp)(?::\s*|\s+)|(?=(?:s\d+\.)?dp\d+\s*:))'
                    r'(\*?\.?(?:s\d+\.)?[\w-]+)\s*:?\s*$', re.IGNORECASE)
_HIST_RE = re.compile(r'^([A-Za-z_][\w.-]*) \((func|group)\)$')

# Column labels of the table headers, from every release, mapped to field names.
_HDR_LABELS = {
    'max-us': 'max_us', 'max. proc us': 'max_us',
    'avg-us': 'avg_us', 'avg.proc us': 'avg_us', 'avg. proc us': 'avg_us',
    'ave. proc us': 'avg_us',
    'count': 'count', 'total-us': 'total_us',
    'ac-max-us': 'ac_max_us', 'ac-avg-us': 'ac_avg_us',
    'ac-count': 'ac_count', 'ac-total-us': 'ac_total_us',
}
_HDR_RE = re.compile('|'.join(re.escape(k) for k in sorted(_HDR_LABELS, key=len, reverse=True)))
_AVG_KEYS = ('avg_us', 'ac_avg_us')
_ROW_KEYS = ('max_us', 'avg_us', 'count', 'total_us',
             'ac_max_us', 'ac_avg_us', 'ac_count', 'ac_total_us')


def classify_function(name):
    """Returns the category of a function name (see the module docstring)."""
    # Latency counters (e.g. pbp_buf_latency, rsa_sign_hw_latency) measure waits, not CPU time.
    if name.endswith('_latency') or \
            pow_glossary.lookup(name)['category'] == pow_glossary.LATENCY_CATEGORY:
        return 'latency'
    if name in L7_FUNCS:
        return 'L7'
    if name in DECRYPT_FUNCS or name.startswith(DECRYPT_PREFIXES):
        return 'DECRYPT'
    if name in TUNNEL_FUNCS:
        return 'TUNNEL'
    if name in URL_FUNCS:
        return 'URL'
    return 'other'


def _new_view():
    return {'groups': [], 'funcs': [], 'hist': []}


def _header_columns(text):
    return [_HDR_LABELS[m.group(0)] for m in _HDR_RE.finditer(text)]


def _parse_row(text, cols):
    parts = text.split()
    name = parts[0].lstrip(':')
    vals = parts[1:]
    if not name or len(vals) != len(cols):
        return None
    row = dict.fromkeys(_ROW_KEYS)
    row['name'] = name
    try:
        for key, val in zip(cols, vals):
            row[key] = float(val) if key in _AVG_KEYS else int(val)
    except ValueError:
        return None
    for prefix in ('', 'ac_'):
        if row[prefix + 'total_us'] is None and row[prefix + 'count'] is not None \
                and row[prefix + 'avg_us'] is not None:
            row[prefix + 'total_us'] = round(row[prefix + 'count'] * row[prefix + 'avg_us'])
    return row


def _parse_bin(text):
    parts = text.split()
    if len(parts) != 5:
        return None
    try:
        col, ticks, cnt, tot = (int(parts[i]) for i in (0, 1, 3, 4))
        avg = float(parts[2])
    except ValueError:
        return None
    return (col, ticks, avg, cnt, tot)


def parse_pow(lines, src=None):
    """Parses the lines of a CLI text file (or of a single command output).

    Returns {'format': 'modern'|'legacy', 'collected_at': str|None, 'warnings': [...],
    'global': view, 'cores': {core: view}} where view = {'groups': [rows],
    'funcs': [rows], 'hist': [histograms]}. A row is a dict with the keys name,
    max_us, avg_us, count, total_us and ac_max_us, ac_avg_us, ac_count, ac_total_us
    (None when the column is absent). A histogram is {name, kind, bins} where each
    bin is the tuple (col, avg_ticks, avg_us, count, total_us).
    """
    prefix = f'{src}: ' if src else ''
    warnings = []
    result = {'format': 'modern', 'collected_at': None, 'warnings': warnings,
              'global': _new_view(), 'cores': {}}
    kinds = set()
    have_global = False
    section = None        # None | 'global' | 'cores' | 'error' | 'dup'
    cmd_label = ''
    view = None           # view that receives the rows of the current section
    table = None          # rows list of the current group/func table
    cols = None
    hist = None
    hist_rows = False     # True after the histogram 'col' header
    clock_pending = False
    first_dp = None

    for raw in lines:
        line = raw.rstrip()
        prompt = _PROMPT_RE.match(line)
        if line.startswith('> ') or prompt:
            cmd = (prompt.group(1) if prompt else line[2:]).strip()
            table = cols = hist = None
            hist_rows = False
            section = None
            clock_pending = cmd == 'show clock'
            if cmd in _CMD_GLOBAL:
                if have_global:
                    warnings.append(prefix + 'second global POW section ignored')
                    section = 'dup'
                else:
                    have_global = True
                    section, view = 'global', result['global']
            else:
                m = _CMD_CORES_RE.match(cmd)
                if m:
                    section, view = 'cores', None
                    cmd_label = f'core {m.group(1)}-{m.group(2)}'
            continue

        stripped = line.strip()
        if clock_pending:
            if stripped:
                clock_pending = False
                if _CLOCK_RE.match(stripped):
                    result['collected_at'] = stripped
            continue
        m = _DP_RE.match(stripped)
        if m and not stripped.startswith('group') and not stripped.startswith('func'):
            dp = m.group(1).lstrip('*.')
            if first_dp is None:
                first_dp = dp
            elif dp != first_dp:
                warnings.append(f'{prefix}several dataplanes in the output: only {first_dp} '
                                f'is analysed, {dp} and later ones are ignored')
                section = 'dup'
            table = cols = hist = None
            hist_rows = False
            continue
        if section is None and not have_global and _TABLE_RE.match(stripped):
            # Plain output without the command line (e.g. a pasted text file): the first
            # valid group/func header starts the global section.
            kind_word = _TABLE_RE.match(stripped).group(1)
            if {'max_us', 'avg_us', 'count'} <= set(_header_columns(stripped[len(kind_word):])):
                have_global = True
                section, view = 'global', result['global']
        if section in (None, 'dup', 'error'):
            continue
        if not stripped:
            continue      # blank lines never end a table or a histogram: the next header does

        if section == 'cores':
            if stripped.startswith('Server error'):
                detail = stripped.split(':', 1)[1].strip()[:120] or 'no detail'
                warnings.append(f'{prefix}pow performance all {cmd_label}: '
                                f'Server error ({detail}), skipped')
                section = 'error'
                continue
            m = _CORE_RE.match(stripped)
            if m:
                view = result['cores'].setdefault(int(m.group(1)), _new_view())
                table = cols = hist = None
                hist_rows = False
                continue
        if view is None:
            continue

        if hist is not None and stripped.startswith('col ') and 'avg-ticks' in stripped:
            hist_rows = True
            continue
        if hist is not None and hist_rows and not _HIST_RE.match(stripped) \
                and not _TABLE_RE.match(stripped):
            bin_ = _parse_bin(stripped)
            if bin_ is None:
                warnings.append(f'{prefix}histogram {hist["name"]}: unexpected row ignored')
            else:
                hist['bins'].append(bin_)
            continue
        m = _HIST_RE.match(stripped)
        if m:
            hist = {'name': m.group(1), 'kind': m.group(2), 'bins': []}
            view['hist'].append(hist)
            table = cols = None
            continue
        m = _TABLE_RE.match(stripped)
        if m:
            hist = None
            cols = _header_columns(stripped[len(m.group(1)):])
            if not {'max_us', 'avg_us', 'count'} <= set(cols):
                warnings.append(f'{prefix}unrecognised table header ignored: '
                                f'{stripped[:60]!r}')
                table = None
                continue
            kinds.add('modern' if 'total_us' in cols else 'legacy')
            table = view['groups'] if m.group(1) == 'group' else view['funcs']
            continue
        if table is not None:
            row = _parse_row(stripped, cols)
            if row is None:
                warnings.append(f'{prefix}unparseable row ignored: {stripped[:60]!r}')
            else:
                table.append(row)

    if kinds:
        result['format'] = 'legacy' if kinds == {'legacy'} else 'modern'
    return result


def has_data(parsed):
    """True when the parsed output holds at least one table row or histogram."""
    views = [parsed['global']] + list(parsed['cores'].values())
    return any(v['groups'] or v['funcs'] or v['hist'] for v in views)


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------
def _pct(part, total):
    return round(100.0 * part / total, 2) if total else 0.0


def _flag(row, code, level, text):
    row['flags'].append({'code': code, 'level': level, 'text': text})


def _eval_table(rows, kind, modern, th):
    for r in rows:
        r['category'] = 'workgroup' if kind == 'group' else classify_function(r['name'])
    # Latency counters measure wall-clock waits, not CPU time: keep them out of the
    # CPU totals, shares and top-N ranking (they stay visible, with share 0).
    cpu_rows = [r for r in rows if r['category'] != 'latency']
    total = sum(r['total_us'] or 0 for r in cpu_rows)
    ac_total = sum(r['ac_total_us'] or 0 for r in cpu_rows) if modern else 0
    for r in rows:
        r['description'] = WORKGROUP_DESCRIPTIONS.get(r['name'], '') if kind == 'group' else ''
        lat = r['category'] == 'latency'
        r['share'] = 0.0 if lat else _pct(r['total_us'] or 0, total)
        r['ac_share'] = 0.0 if lat else _pct(r['ac_total_us'] or 0, ac_total)
        r['ratio'] = None
        if modern and r['ac_count']:
            r['ratio'] = round((r['count'] or 0) / r['ac_count'], 2)
        r['flags'] = []
        g = pow_glossary.lookup(r['name'])
        r['gcategory'], r['gconf'] = g['category'], g['conf']
        r['known'] = r['name'] in pow_glossary.GLOSSARY

    top_n = th['top_n']
    ranked = sorted((r for r in cpu_rows if (r['total_us'] or 0) > 0),
                    key=lambda r: -r['total_us'])[:top_n]
    for r in ranked:
        if r['share'] >= th['share_warn']:
            level = 'crit' if r['share'] >= th['share_crit'] else 'warn'
            _flag(r, 'TOP_CPU', level,
                  f"top {top_n} by total-us: {r['share']:.1f}% of the table CPU time")
    if modern:
        ranked = sorted((r for r in cpu_rows if (r['ac_total_us'] or 0) > 0),
                        key=lambda r: -r['ac_total_us'])[:top_n]
        for r in ranked:
            if r['ac_share'] >= th['share_warn']:
                _flag(r, 'TOP_CPU_ACC', 'info',
                      f"top {top_n} by ac-total-us since boot: {r['ac_share']:.1f}%")

    for r in rows:
        mx, avg, cnt = r['max_us'] or 0, r['avg_us'] or 0.0, r['count'] or 0
        if mx >= th['max_spike_abs_us'] and cnt >= th['min_count'] and \
                (avg <= 0 or mx / avg >= th['max_spike_ratio']):
            level = 'crit' if mx >= th['max_spike_crit_us'] else 'warn'
            _flag(r, 'MAX_SPIKE', level, f'max-us {mx} vs avg-us {avg:g} over {cnt} calls')
        if not modern:
            continue
        amx, aavg = r['ac_max_us'] or 0, r['ac_avg_us'] or 0.0
        acnt = r['ac_count'] or 0
        if amx >= th['max_spike_abs_us'] and acnt >= th['min_count'] and \
                (aavg <= 0 or amx / aavg >= th['max_spike_ratio']):
            _flag(r, 'MAX_SPIKE_ACC', 'info',
                  f'ac-max-us {amx} vs ac-avg-us {aavg:g} since boot')
        if avg >= th['drift_min_avg_us'] and cnt >= th['min_count'] and \
                acnt >= th['min_count'] and aavg > 0 and avg >= th['drift_ratio'] * aavg:
            level = 'crit' if avg >= th['drift_crit_ratio'] * aavg else 'warn'
            _flag(r, 'AVG_DRIFT', level,
                  f'avg-us {avg:g} is {avg / aavg:.1f}x the since-boot avg-us {aavg:g}')
        if cnt == 0 and amx >= th['max_spike_abs_us']:
            _flag(r, 'HISTORICAL_ONLY', 'info',
                  f'no calls in this window; ac-max-us {amx} since boot')

    for r in rows:
        avg, cnt = r['avg_us'] or 0.0, r['count'] or 0
        if r['category'] == 'latency' and avg >= th['latency_high_us'] and cnt >= th['min_count']:
            _flag(r, 'LATENCY_HIGH', 'info',
                  f'latency counter (not CPU time): avg-us {avg:g} over {cnt} events')
        ever = cnt or r['total_us'] or r['ac_count'] or r['ac_total_us'] or r['ac_max_us']
        if (r['gconf'] == 'U' or r['gcategory'] == 'Unclassified') and ever:
            _flag(r, 'UNKNOWN', 'warn' if cnt or r['total_us'] else 'info',
                  'no known meaning for this counter; please report it so the glossary can grow')
        limit = th['high_avg_us_decrypt'] if r['category'] == 'DECRYPT' else th['high_avg_us']
        if avg >= limit and cnt >= th['min_count'] and r['category'] != 'latency':
            _flag(r, 'HIGH_AVG', 'warn', f'avg-us {avg:g} over {cnt} calls (limit {limit})')


def _category_summary(rows, modern, th):
    basis, key = None, None
    rows = [r for r in rows if r['category'] != 'latency']
    if sum(r['total_us'] or 0 for r in rows) > 0:
        basis, key = 'current', 'total_us'
    elif modern and sum(r['ac_total_us'] or 0 for r in rows) > 0:
        basis, key = 'accumulated', 'ac_total_us'
    if key is None:
        return {'basis': None, 'total_us': 0, 'by_category': [], 'dominant': []}
    total = sum(r[key] or 0 for r in rows)
    agg = {}
    for r in rows:
        agg[r['category']] = agg.get(r['category'], 0) + (r[key] or 0)
    by_cat = [{'category': c, 'total_us': v, 'share': _pct(v, total)}
              for c, v in sorted(agg.items(), key=lambda kv: -kv[1])]
    dominant = [b['category'] for b in by_cat
                if b['category'] != 'other' and b['share'] >= th['category_dominance']]
    return {'basis': basis, 'total_us': total, 'by_category': by_cat, 'dominant': dominant}


def _gloss_summary(rows):
    """Roll-up of the CPU-time functions by glossary family (nothing is dropped)."""
    cpu = [r for r in rows if r['category'] != 'latency']
    tot = sum(r['total_us'] or 0 for r in cpu)
    atot = sum(r['ac_total_us'] or 0 for r in cpu)
    fam = {}
    for r in cpu:
        c = fam.setdefault(r['gcategory'], {'category': r['gcategory'], 'funcs': 0, 'active': 0,
                                            'total_us': 0, 'ac_total_us': 0, 'zero': True,
                                            'unknown': 0, 'top': None, '_top_us': 0})
        c['funcs'] += 1
        c['active'] += 1 if (r['count'] or r['total_us']) else 0
        c['total_us'] += r['total_us'] or 0
        c['ac_total_us'] += r['ac_total_us'] or 0
        c['zero'] = c['zero'] and not any(r[k] for k in _ROW_KEYS)
        c['unknown'] += 0 if r['known'] else 1
        if (r['total_us'] or 0) > c['_top_us']:
            c['top'], c['_top_us'] = r['name'], r['total_us']
    order = {n: i for i, n in enumerate(pow_glossary.CATEGORY_ORDER)}
    out = []
    for c in fam.values():
        c.pop('_top_us')
        c['share'] = _pct(c['total_us'], tot)
        c['ac_share'] = _pct(c['ac_total_us'], atot)
        out.append(c)
    out.sort(key=lambda c: (-c['total_us'], order.get(c['category'], 999), c['category']))
    return out


def _eval_hist(h, th):
    bins = h['bins']
    total = sum(b[3] for b in bins)
    h['count'] = total
    h['p50_us'] = h['p99_us'] = h['max_bin_us'] = None
    h['flags'] = []
    if not total:
        return

    def percentile(q):
        cum = 0
        for b in sorted(bins, key=lambda b: b[2]):
            cum += b[3]
            if cum >= q * total:
                return b[2]
        return None

    h['p50_us'] = percentile(0.5)
    h['p99_us'] = percentile(0.99)
    h['max_bin_us'] = max(b[2] for b in bins if b[3] > 0)
    worst = None
    for col, _ticks, avg, cnt, _tot in bins:
        share = 100.0 * cnt / total
        if cnt >= 1 and avg >= th['hist_tail_us'] and share < th['hist_tail_share']:
            level = 'crit' if avg >= th['hist_tail_crit_us'] else 'warn'
            if worst is None or level == 'crit':
                worst = (level, (f'{cnt} call(s) at {avg:g} us (bin {col}), '
                                 f'{share:.3f}% of {total} calls'))
            if level == 'crit':
                break
    if worst:
        h['flags'].append({'code': 'TAIL', 'level': worst[0], 'text': worst[1]})
    time_total = sum(b[4] for b in bins)
    slow = [b for b in bins if b[3] and b[4] / b[3] >= th['hist_slow_us']]
    slow_calls, slow_time = sum(b[3] for b in slow), sum(b[4] for b in slow)
    if time_total and slow_calls >= th['hist_slow_min_count'] and \
            100.0 * slow_time / time_total >= th['hist_slow_share'] and \
            h['kind'] == 'func' and classify_function(h['name']) != 'latency':
        h['flags'].append({'code': 'HIST_SLOW', 'level': 'warn',
                           'text': f'{100.0 * slow_time / time_total:.1f}% of the time '
                                   f'({slow_calls} calls) is spent in bins slower than '
                                   f"{th['hist_slow_us']} us"})


def _eval_view(view, modern, th):
    _eval_table(view['groups'], 'group', modern, th)
    _eval_table(view['funcs'], 'func', modern, th)
    view['func_summary'] = _category_summary(view['funcs'], modern, th)
    view['gloss_summary'] = _gloss_summary(view['funcs'])
    for h in view['hist']:
        _eval_hist(h, th)


def _eval_cores(out, th):
    totals = {}
    for n in sorted(out['cores']):
        view = out['cores'][n]
        totals[n] = {'group_total_us': sum(r['total_us'] or 0 for r in view['groups']),
                     'func_total_us': sum(r['total_us'] or 0 for r in view['funcs'])}
    active = [n for n in totals if totals[n]['group_total_us'] > 0]
    idle = [n for n in totals if totals[n]['group_total_us'] == 0]
    median = None
    flags = {}
    if len(active) >= th['min_active_cores']:
        median = statistics.median(totals[n]['group_total_us'] for n in active)
        for n in active:
            ratio = totals[n]['group_total_us'] / median
            if ratio >= th['core_imbalance_ratio']:
                level = 'crit' if ratio >= 2 * th['core_imbalance_ratio'] else 'warn'
                flags[n] = [{'code': 'CORE_IMBALANCE', 'level': level,
                             'text': f'workgroup total-us {ratio:.1f}x the median '
                                     f'of {len(active)} active cores'}]
    out['core_summary'] = {'cores': totals, 'active': active, 'idle': idle,
                           'median_group_total_us': median, 'flags': flags}


def _banner(out, th):
    items = []
    if out['format'] == 'legacy':
        items.append({'level': 'info', 'text': 'Legacy (pre-9.1) output: no total-us or '
                      'ac-* columns, so AVG_DRIFT, *_ACC flags and the count ratio are not '
                      'available.'})
    g = out['global']
    summary = g['func_summary']
    for cat in summary['dominant']:
        share = next(b['share'] for b in summary['by_category'] if b['category'] == cat)
        items.append({'level': 'warn', 'text': f'{cat} is {share:.0f}% of function CPU time '
                      f'({summary["basis"]} counters)'})
    rows = g['groups'] + g['funcs']
    crit = sum(1 for r in rows if any(f['level'] == 'crit' for f in r['flags']))
    warn = sum(1 for r in rows if any(f['level'] == 'warn' for f in r['flags'])
               and not any(f['level'] == 'crit' for f in r['flags']))
    if crit or warn:
        items.append({'level': 'crit' if crit else 'warn',
                      'text': f'Global view: {crit} row(s) critical, {warn} row(s) warning'})
    tails = sum(1 for h in g['hist'] if any(f['code'] == 'TAIL' for f in h['flags']))
    if tails:
        items.append({'level': 'warn', 'text': f'{tails} histogram(s) with a rare long tail'})
    slow = [h['name'] for h in g['hist'] if any(f['code'] == 'HIST_SLOW' for f in h['flags'])]
    if slow:
        items.append({'level': 'warn', 'names': slow[:10],
                      'text': 'Histogram time spent in slow bins (HIST_SLOW): ' + ', '.join(slow[:10])
                              + (f' (+{len(slow) - 10} more)' if len(slow) > 10 else '')})
    dec = next((b['share'] for b in summary['by_category'] if b['category'] == 'DECRYPT'), 0)
    if th['decrypt_share_warn'] <= dec and 'DECRYPT' not in summary['dominant']:
        items.append({'level': 'warn', 'text': f'DECRYPT is {dec:.0f}% of function CPU time '
                      f'({summary["basis"]} counters). Check the decryption policy scope, '
                      f'handshake rate and crypto offload.'})
    unk = [r['name'] for r in rows if any(f['code'] == 'UNKNOWN' for f in r['flags'])]
    unk = list(dict.fromkeys(unk))
    if unk:
        items.append({'level': 'warn', 'names': unk[:15],
                      'text': f'{len(unk)} counter(s) with no known meaning are non-zero: '
                              + ', '.join(unk[:15]) + (f' (+{len(unk) - 15} more)' if len(unk) > 15 else '')
                              + '. Please report them so the glossary can grow.'})
    cs = out['core_summary']
    for n, fl in sorted(cs['flags'].items()):
        items.append({'level': fl[0]['level'], 'text': f'core {n}: {fl[0]["text"]}'})
    if cs['idle']:
        items.append({'level': 'info', 'text': 'Cores with no workgroup activity in this '
                      'window: ' + ', '.join(str(n) for n in cs['idle'])})
    return items


def evaluate(parsed, thresholds=None):
    """Adds flags, shares and summaries to a parse_pow() result.

    Returns a new, JSON-serialisable dict with the same shape as the input plus:
    'thresholds' (values used), 'banner' (list of {level, text}), 'core_summary'
    (per-core totals, idle and imbalanced cores), and for every view a 'func_summary'
    and, per row, 'category', 'description', 'share', 'ac_share', 'ratio' and 'flags'.
    The input is not modified.
    """
    th = dict(POW_THRESHOLDS)
    unknown = set(thresholds or {}) - set(POW_THRESHOLDS)
    if unknown:
        raise ValueError('unknown POW threshold(s): ' + ', '.join(sorted(unknown)))
    th.update(thresholds or {})
    out = copy.deepcopy(parsed)
    modern = out['format'] == 'modern'
    _eval_view(out['global'], modern, th)
    for view in out['cores'].values():
        _eval_view(view, modern, th)
    _eval_cores(out, th)
    out['thresholds'] = th
    out['banner'] = _banner(out, th)
    return out
