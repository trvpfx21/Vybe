"""End-to-end test of the VIP feature against a running server (dev only)."""
import json, sqlite3, urllib.request, urllib.error, os

BASE = os.environ.get('VYBE_TEST_BASE', 'http://127.0.0.1:8004')
DB = 'data/nightlife.db'
ok = True

def req(path, data=None, ck=None, method=None):
    headers = {'Content-Type': 'application/json'}
    if ck:
        headers['Cookie'] = ck
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, data=body, headers=headers,
                               method=method or ('POST' if data is not None else 'GET'))
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read().decode() or '{}'
            newck = ck
            if not newck and 'Set-Cookie' in resp.headers:
                newck = resp.headers['Set-Cookie'].split(';')[0]
            return resp.status, newck, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or '{}'
        try:
            j = json.loads(raw)
        except Exception:
            j = {'error': raw[:200]}
        return e.code, ck, j

def login(em, pw):
    s, ck, j = req('/api/login', {'email': em, 'password': pw})
    assert s == 200, (s, j)
    return ck

def uid_of(em):
    con = sqlite3.connect(DB)
    row = con.execute('SELECT id FROM users WHERE email=?', (em,)).fetchone()
    con.close()
    return row[0]

def check(name, cond, extra=''):
    global ok
    print(('PASS  ' if cond else 'FAIL  ') + name + ('' if cond else ' -> ' + str(extra)))
    if not cond:
        ok = False

import server as S

con = sqlite3.connect(DB)
con.execute("DELETE FROM users WHERE email='tmp-vip-admin@dev.local'")
con.commit()
cur = con.execute(
    "INSERT INTO users(name,email,role,password,status) VALUES(?,?,?,?,?)",
    ('Temp VIP Admin', 'tmp-vip-admin@dev.local', 'admin', S.pw_hash('TmpAdmin!2026'), 'active'))
AID = cur.lastrowid
con.commit()
vip_profile_id = con.execute("SELECT id FROM profiles WHERE display_name='Nia Rose'").fetchone()[0]
# The cases below exercise VIP-only access; establish that fixture explicitly
# instead of depending on stale database state from a prior manual/test run.
con.execute('UPDATE profiles SET is_vip=1 WHERE id=?', (vip_profile_id,))
con.commit()
con.close()

try:
    # Reset fixtures so the run is repeatable regardless of prior demo/manual state.
    con = sqlite3.connect(DB)
    c2fix = uid_of('customer2@nightlife.test')
    c1fix = uid_of('customer1@nightlife.test')
    con.execute('DELETE FROM saved_profiles WHERE user_id IN (?,?)', (c1fix, c2fix))
    con.execute('DELETE FROM messages WHERE customer_id=?', (c2fix,))
    con.execute('DELETE FROM vip_membership_history WHERE membership_id IN (SELECT id FROM vip_memberships WHERE user_id=?)', (c2fix,))
    con.execute('DELETE FROM vip_memberships WHERE user_id=?', (c2fix,))
    con.commit()
    con.close()
    adminck = login('tmp-vip-admin@dev.local', 'TmpAdmin!2026')
    s, _, me = req('/api/me', ck=adminck)
    check('admin login', s == 200 and me.get('user', {}).get('role') == 'admin', me)
    c2 = uid_of('customer2@nightlife.test')
    c2ck = login('customer2@nightlife.test', 'EmpireDemo!2026')

    # ---------- anonymous ----------
    s, _, lst = req('/api/profiles')
    ids = [p['id'] for p in lst]
    check('anon: VIP profile hidden from directory', vip_profile_id not in ids, ids[:5])
    s, _, j = req('/api/profiles/%d' % vip_profile_id)
    check('anon: VIP-only profile returns vip_required 403', s == 403 and j.get('code') == 'vip_required', (s, j))
    s, _, j = req('/api/profiles/%d' % ids[0])
    check('anon: standard profile browsable', s == 200, (s, j))

    # ---------- standard user ----------
    s, _, j = req('/api/vip', ck=c2ck)
    check('standard user: GET /api/vip status none', s == 200 and j.get('membership', {}).get('status') == 'none', (s, j))
    s, _, j = req('/api/profiles/%d' % vip_profile_id, ck=c2ck)
    check('standard user: VIP-only profile blocked', s == 403 and j.get('code') == 'vip_required', (s, j))
    s, _, j = req('/api/vip/request', {}, ck=c2ck)
    check('standard user: can request membership', s == 201 and j.get('status') == 'pending', (s, j))
    s, _, j = req('/api/vip', ck=c2ck)
    check('standard user: status now pending', j.get('membership', {}).get('status') == 'pending', j)
    s, _, j = req('/api/vip/request', {}, ck=c2ck)
    check('standard user: duplicate request rejected', s == 400, (s, j))
    s, _, j = req('/api/saved', {'profile_id': ids[0]}, ck=c2ck)
    check('standard user: can save standard profile', s == 200 and j.get('saved') is True, (s, j))
    s, _, j = req('/api/saved', {'profile_id': vip_profile_id}, ck=c2ck)
    check('standard user: cannot save VIP-only profile', s == 403 and j.get('code') == 'vip_required', (s, j))
    s, _, j = req('/api/messages', {'profile_id': vip_profile_id, 'body': 'hi'}, ck=c2ck)
    check('standard user: cannot message VIP provider', s == 403 and j.get('code') == 'vip_required', (s, j))

    # ---------- admin VIP dashboard ----------
    s, _, j = req('/api/admin/vip', ck=adminck)
    check('admin: VIP dashboard loads', s == 200 and 'members' in j and 'profiles' in j and 'history' in j,
          list(j) if isinstance(j, dict) else (s, j))
    s, _, st = req('/api/stats', ck=adminck)
    check('admin: stats expose vip_profiles/vip_clients', 'vip_profiles' in st and 'vip_clients' in st, st)

    # ---------- designate / remove VIP ----------
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    prov2 = con.execute('SELECT provider_id FROM profiles WHERE id=?', (ids[0],)).fetchone()['provider_id']
    con.close()
    s, _, j = req('/api/admin/provider/%d' % prov2, {'is_vip': True}, ck=adminck)
    check('admin: designate approved profile as VIP', s == 200, (s, j))
    s, _, j = req('/api/profiles/%d' % ids[0])
    check('designated profile becomes VIP-only for anon', s == 403 and j.get('code') == 'vip_required', (s, j))
    s, _, j = req('/api/admin/provider/%d' % prov2, {'is_vip': False}, ck=adminck)
    check('admin: remove VIP status', s == 200, (s, j))
    s, _, j = req('/api/profiles/%d' % ids[0])
    check('de-designated profile back to normal approved', s == 200 and j.get('is_vip') is False, (s, j))

    # ---------- membership lifecycle ----------
    s, _, j = req('/api/admin/vipmember', {'action': 'activate', 'user_id': c2, 'days': 2}, ck=adminck)
    check('admin: activate membership', s == 200 and j.get('expires_at'), (s, j))
    s, _, j = req('/api/vip', ck=c2ck)
    check('member: /api/vip active with expires_at', j.get('membership', {}).get('status') == 'active' and j.get('membership', {}).get('expires_at'), j)
    s, _, me = req('/api/me', ck=c2ck)
    check('member: /api/me exposes vip state', me.get('vip', {}).get('status') == 'active' and me.get('user', {}).get('is_vip') == 1, me)
    s, _, j = req('/api/profiles/%d' % vip_profile_id, ck=c2ck)
    check('member: can open VIP-only profile', s == 200 and j.get('is_vip') is True, (s, j))
    s, _, lst2 = req('/api/profiles', ck=c2ck)
    check('member: VIP profile visible in directory', vip_profile_id in [p['id'] for p in lst2])
    s, _, j = req('/api/saved', {'profile_id': vip_profile_id}, ck=c2ck)
    check('member: can save VIP profile', s == 200 and j.get('saved') is True, (s, j))
    s, _, j = req('/api/saved', ck=c2ck)
    check('member: saved list returns it', any(p.get('profile_id') == vip_profile_id for p in j), j)
    s, _, j = req('/api/messages', {'profile_id': vip_profile_id, 'body': 'Hello from an active VIP member'}, ck=c2ck)
    check('member: can message VIP provider', s == 201, (s, j))
    s, _, j = req('/api/messages?profile_id=%d' % vip_profile_id, ck=c2ck)
    check('member: VIP thread readable', s == 200 and len(j.get('messages', [])) >= 1, (s, j))

    # ---------- suspend ----------
    s, _, j = req('/api/admin/vipmember', {'action': 'suspend', 'user_id': c2}, ck=adminck)
    check('admin: suspend membership', s == 200 and j.get('status') == 'suspended', (s, j))
    s, _, j = req('/api/vip', ck=c2ck)
    check('suspended: /api/vip shows suspended', j.get('membership', {}).get('status') == 'suspended', j)
    s, _, j = req('/api/profiles/%d' % vip_profile_id, ck=c2ck)
    check('suspended: VIP-only profile blocked again', s == 403 and j.get('code') == 'vip_required', (s, j))

    # ---------- expiry ----------
    s, _, j = req('/api/admin/vipmember', {'action': 'activate', 'user_id': c2, 'days': 1}, ck=adminck)
    con = sqlite3.connect(DB)
    con.execute("UPDATE vip_memberships SET expires_at='2020-01-01 00:00:00' WHERE user_id=?", (c2,))
    con.commit()
    con.close()
    s, _, j = req('/api/vip', ck=c2ck)
    check('expired: status expired after past expiry', j.get('membership', {}).get('status') == 'expired', (s, j))
    s, _, me = req('/api/me', ck=c2ck)
    check('expired: standard account active, is_vip cleared', me.get('user', {}).get('status') == 'active' and me.get('user', {}).get('is_vip') == 0, me)
    s, _, j = req('/api/profiles/%d' % vip_profile_id, ck=c2ck)
    check('expired: VIP-only access removed', s == 403 and j.get('code') == 'vip_required', (s, j))
    s, _, j = req('/api/saved', ck=c2ck)
    check('expired: saved VIP profile filtered out', all(p.get('profile_id') != vip_profile_id for p in j), j)

    # ---------- renew ----------
    s, _, j = req('/api/vip/request', {}, ck=c2ck)
    check('expired: renew request accepted', s == 201 and j.get('status') == 'pending', (s, j))
    s, _, j = req('/api/admin/vipmember', {'action': 'renew', 'user_id': c2, 'days': 7}, ck=adminck)
    check('admin: renew membership', s == 200 and j.get('expires_at'), (s, j))
    s, _, j = req('/api/vip', ck=c2ck)
    check('renewed: active again', j.get('membership', {}).get('status') == 'active', j)
    s, _, j = req('/api/profiles/%d' % vip_profile_id, ck=c2ck)
    check('renewed: VIP access restored', s == 200, (s, j))

    # ---------- setexpiry ----------
    s, _, j = req('/api/admin/vipmember', {'action': 'setexpiry', 'user_id': c2, 'days': 14}, ck=adminck)
    check('admin: set expiry (days)', s == 200 and j.get('expires_at'), (s, j))

    # ---------- history ----------
    s, _, j = req('/api/admin/vip', ck=adminck)
    hist = [h['action'] for h in j.get('history', [])]
    check('admin: membership history recorded',
          set(['requested', 'activated', 'suspend', 'expired', 'renewed', 'expiry_set']).issubset(set(hist)), hist)
    check('admin: history names the member', all('member_name' in h for h in j.get('history', [])), j.get('history', [])[:2])

    # ---------- enforcement ----------
    s, _, j = req('/api/admin/vip', ck=c2ck)
    check('non-admin blocked from admin VIP dashboard', s == 403, (s, j))
    s, _, j = req('/api/admin/vipmember', {'action': 'activate', 'user_id': c2}, ck=c2ck)
    check('non-admin blocked from membership mutations', s == 403, (s, j))
    s, _, j = req('/api/admin/vip')
    check('anon blocked from admin VIP dashboard', s == 403, (s, j))

    # ---------- tidy demo state ----------
    con = sqlite3.connect(DB)
    con.execute('DELETE FROM saved_profiles WHERE user_id=?', (c2,))
    con.execute('DELETE FROM messages WHERE customer_id=?', (c2,))
    con.execute('DELETE FROM vip_memberships WHERE user_id=?', (c2,))
    con.execute('DELETE FROM vip_membership_history WHERE membership_id NOT IN (SELECT id FROM vip_memberships)')
    c1 = uid_of('customer1@nightlife.test')
    con.commit()
    con.close()
    s, _, j = req('/api/admin/vipmember', {'action': 'activate', 'user_id': c1, 'days': 365}, ck=adminck)
    check('demo: customer1 given 365-day VIP membership', s == 200 and j.get('expires_at'), (s, j))
finally:
    con = sqlite3.connect(DB)
    con.execute('DELETE FROM audit WHERE admin_id=?', (AID,))
    con.execute("DELETE FROM users WHERE email='tmp-vip-admin@dev.local'")
    con.commit()
    con.close()

print('')
print('RESULT:', 'ALL PASS' if ok else 'FAILURES PRESENT')
raise SystemExit(0 if ok else 1)
