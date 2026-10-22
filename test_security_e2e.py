"""End-to-end security tests for VYBE authentication (dev only).

Run with a server started with VYBE_DEV_RESET_LINK=1 so the reset link is returned
(no SMTP configured locally). Exercises password hashing, reset flow, TOTP 2FA,
rate limiting, CSRF/origin checks, security headers and admin RBAC.
"""
import json, sqlite3, time, base64, hmac, hashlib, struct, urllib.request, urllib.error, os

BASE = os.environ.get('VYBE_TEST_BASE', 'http://127.0.0.1:8011')
DB = 'data/nightlife.db'
ok = True

def req(path, data=None, ck=None, method=None, origin=None):
    headers = {'Content-Type': 'application/json'}
    if ck: headers['Cookie'] = ck
    if origin: headers['Origin'] = origin
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, data=body, headers=headers,
                               method=method or ('POST' if data is not None else 'GET'))
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode() or '{}'
            newck = ck
            setc = resp.headers.get('Set-Cookie', '')
            if 'ne_session=' in setc:
                pair = [p for p in setc.split(';') if p.strip().startswith('ne_session=')]
                if pair: newck = pair[0].strip()
            return resp.status, newck, json.loads(raw), resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or '{}'
        try: j = json.loads(raw)
        except Exception: j = {'error': raw[:200]}
        return e.code, ck, j, e.headers

def get_status(path, method='GET'):
    try:
        request = urllib.request.Request(BASE + path, method=method)
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code

def check(name, cond, extra=''):
    global ok
    print(('PASS  ' if cond else 'FAIL  ') + name + ('' if cond else ' -> ' + str(extra)))
    if not cond: ok = False

def totp(secret, offset=0):
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    counter = int(time.time() // 30) + offset
    h = hmac.new(key, counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    o = h[-1] & 0x0f
    return f'{(struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 10**6:06d}'

def uid_of(em):
    con = sqlite3.connect(DB)
    row = con.execute('SELECT id FROM users WHERE email=?', (em,)).fetchone()
    con.close()
    return row[0] if row else None

def conn():
    return sqlite3.connect(DB)

EM = 'sec-user@dev.local'
PW = 'Corr3ct-Horse!9'
NEW_PW = 'Tr0ub4dor&3-Xk'

# clean slate
c = conn()
c.execute("DELETE FROM auth_events WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM password_resets WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM users WHERE email LIKE 'sec-%@dev.local'")
c.commit(); c.close()

# ---- password storage ----
import server as S
check('home page is served', get_status('/') == 200)
check('database files are not served', get_status('/data/nightlife.db') == 404)
check('server source is not served', get_status('/server.py') == 404)
check('private launch backup is not served', get_status('/data/prelaunch-backup-2026-10-12.zip') == 404)
check('HEAD cannot bypass the static-file allowlist', get_status('/data/nightlife.db', 'HEAD') == 405)
h = S.pw_hash(PW)
check('hash is scrypt, not plaintext', h.startswith('scrypt$') and PW not in h, h[:40])
check('same password hashes differently (unique salt)', S.pw_hash(PW) != h)
check('verify accepts correct password', S.verify(PW, h))
check('verify rejects wrong password', not S.verify('wrong-pass-123', h))
check('legacy salt:dk format still verifies',
      S.verify(PW, 'aabb:' + __import__('hashlib').scrypt(PW.encode(), salt=bytes.fromhex('aabb'), n=2**14, r=8, p=1, maxmem=64*1024*1024).hex()))
check('password policy rejects weak', bool(S.password_issues('password', 'customer', EM, 'Sec')))
check('password policy accepts strong', not S.password_issues(PW, 'customer', EM, 'Sec'))

# ---- registration ----
s, _, j, _ = req('/api/register', {'role': 'customer', 'name': 'Sec User', 'email': EM,
                                   'phone': '0700000000', 'password': 'weak', 'passwordConfirm': 'weak'})
check('register rejects weak password', s == 400, (s, j))
s, _, j, _ = req('/api/register', {'role': 'customer', 'name': 'Sec User', 'email': EM,
                                   'phone': '0700000000', 'password': PW, 'passwordConfirm': PW})
check('register accepts strong password', s == 201, (s, j))

# ---- login + enumeration + headers ----
s, _, j, hdr = req('/api/login', {'email': 'nobody-here@dev.local', 'password': 'whatever-123'})
check('unknown email: generic 401 (no enumeration)', s == 401 and 'incorrect' in j.get('error', '').lower(), (s, j))
s, _, j, hdr = req('/api/login', {'email': EM, 'password': 'wrong-Password!1'})
check('wrong password: same generic 401', s == 401 and 'incorrect' in j.get('error', '').lower(), (s, j))
s, ck, j, hdr = req('/api/login', {'email': EM, 'password': PW})
check('correct password: 200 + session cookie', s == 200 and ck and 'ne_session=' in ck, (s, j))
sc = hdr.get('Set-Cookie', '')
check('session cookie is HttpOnly + SameSite=Lax', 'HttpOnly' in sc and 'SameSite=Lax' in sc, sc)
check('security headers present on API', hdr.get('X-Content-Type-Options') == 'nosniff'
      and hdr.get('X-Frame-Options') == 'DENY' and 'default-src' in hdr.get('Content-Security-Policy', ''),
      dict(hdr))
s, _, me, _ = req('/api/me', ck=ck)
check('session works; /api/me never exposes hash', s == 200 and 'password' not in json.dumps(me).lower(), me)

# hash upgraded on login (legacy -> scrypt current cost)
c = conn(); stored = c.execute('SELECT password FROM users WHERE email=?', (EM,)).fetchone()[0]; c.close()
check('legacy hash auto-upgraded on login', stored.startswith('scrypt$'), stored[:20])

# ---- CSRF / origin ----
s, _, j, _ = req('/api/account/password', {'currentPassword': 'x', 'password': 'y'}, ck=ck, origin='https://evil.example')
check('cross-origin POST blocked (CSRF)', s == 403, (s, j))

# ---- password change ----
s, _, j, _ = req('/api/account/password', {'currentPassword': 'wrong', 'password': NEW_PW}, ck=ck)
check('change rejects wrong current password', s in (400, 401), (s, j))
s, _, j, _ = req('/api/account/password', {'currentPassword': PW, 'password': NEW_PW}, ck=ck)
check('change accepts correct current password', s == 200, (s, j))
s, _, j, _ = req('/api/account/password', {'currentPassword': NEW_PW, 'password': PW}, ck=ck)
check('restore original password', s == 200, (s, j))

# ---- forgot / reset ----
s, _, j, _ = req('/api/password/forgot', {'email': 'no-such-user@dev.local'})
check('forgot: generic response for unknown email', s == 200 and 'if an account' in j.get('message', '').lower() and 'dev_reset_link' not in j, (s, j))
s, _, j, _ = req('/api/password/forgot', {'email': EM})
check('forgot: generic response for known email (+dev link)', s == 200 and 'dev_reset_link' in j, list(j))
link = j.get('dev_reset_link', '')
token = link.split('token=')[-1] if 'token=' in link else ''
check('reset token present and long', len(token) >= 32, token[:8])
c = conn()
row = c.execute('SELECT token_hash, expires_at, used FROM password_resets WHERE user_id=? ORDER BY id DESC LIMIT 1', (uid_of(EM),)).fetchone()
c.close()
check('reset token stored hashed (not plaintext)', row and row[0] != token and len(row[0]) == 64, row[0][:12] if row else None)
check('reset token expires in ~30min', row and 1700 <= row[1] - int(time.time()) <= 1810, row[1] - int(time.time()) if row else None)
s, _, j, _ = req('/api/password/reset', {'token': 'bogus-token', 'password': 'Xk!1Pass', 'passwordConfirm': 'Xk!1Pass'})
check('reset rejects bogus token', s == 400, (s, j))
s, _, j, _ = req('/api/password/reset', {'token': token, 'password': 'weak', 'passwordConfirm': 'weak'})
check('reset rejects weak new password', s == 400, (s, j))
s, _, j, _ = req('/api/password/reset', {'token': token, 'password': NEW_PW, 'passwordConfirm': NEW_PW})
check('reset accepts valid token + strong password', s == 200, (s, j))
s, _, j, _ = req('/api/login', {'email': EM, 'password': PW})
check('old password no longer works after reset', s == 401, (s, j))
s, ck2, j, _ = req('/api/login', {'email': EM, 'password': NEW_PW})
check('new password works after reset', s == 200 and ck2, (s, j))
s, _, j, _ = req('/api/password/reset', {'token': token, 'password': 'Zz!9Another1', 'passwordConfirm': 'Zz!9Another1'})
check('reset token single-use (reuse rejected)', s == 400, (s, j))
s, _, j, _ = req('/api/me', ck=ck)
check('sessions invalidated after reset', j.get('user') is None, (s, j))
c = conn(); c.execute('UPDATE users SET password=? WHERE email=?', (S.pw_hash(PW), EM)); c.commit(); c.close()

# ---- rate limiting ----
print('  (rate-limit checks use distinct emails to avoid tripping global lockouts)')
lim_em = 'sec-limit@dev.local'
s, _, j, _ = req('/api/register', {'role': 'customer', 'name': 'Lim User', 'email': lim_em,
                                   'phone': '0700000001', 'password': PW, 'passwordConfirm': PW})
codes = []
for _ in range(8):
    s, _, j, _ = req('/api/login', {'email': lim_em, 'password': 'definitely-wrong-1'})
    codes.append(s)
check('repeated failed logins eventually rate-limited (429)', 429 in codes, codes)
# forgot-password rate limit
fcodes = []
for _ in range(6):
    s, _, j, _ = req('/api/password/forgot', {'email': 'sec-flood@dev.local'})
    fcodes.append(s)
check('repeated forgot requests rate-limited (429)', 429 in fcodes, fcodes)

# ---- RBAC: customer cannot reach admin APIs ----
for p in ['/api/stats', '/api/admin/applications', '/api/admin/admins']:
    s, _, j, _ = req(p, ck=ck)
    check(f'customer blocked from {p}', s == 403, (s, j))

# ---- admin 2FA (TOTP) ----
import server as Ssrv
ad_em = 'sec-admin@dev.local'; ad_pw = 'Adm1n-Str0ng!7'
c = conn()
c.execute("DELETE FROM users WHERE email=?", (ad_em,))
c.execute('INSERT INTO users(name,email,role,password,status,is_super) VALUES(?,?,?,?,?,0)',
          ('Sec Admin', ad_em, 'admin', Ssrv.pw_hash(ad_pw), 'active'))
c.commit(); c.close()
s, ack, j, _ = req('/api/login', {'email': ad_em, 'password': ad_pw})
check('admin signs in before 2FA', s == 200 and ack, (s, j))
s, _, j, _ = req('/api/account/mfa/setup', {'password': 'bad-pw'}, ck=ack)
check('2FA setup rejects wrong password', s == 401, (s, j))
s, _, j, _ = req('/api/account/mfa/setup', {'password': ad_pw}, ck=ack)
check('2FA setup returns secret + otpauth', s == 200 and j.get('secret') and j.get('otpauth', '').startswith('otpauth://'), list(j))
secret = j.get('secret', '')
s, _, j, _ = req('/api/account/mfa/enable', {'code': '000000'}, ck=ack)
wrong_code = '111111' if totp(secret) != '111111' else '222222'
s, _, j, _ = req('/api/account/mfa/enable', {'code': wrong_code}, ck=ack)
check('2FA enable rejects wrong code', s == 401, (s, j))
s, _, j, _ = req('/api/account/mfa/enable', {'code': totp(secret)}, ck=ack)
check('2FA enable accepts valid TOTP', s == 200, (s, j))
req('/api/logout', {}, ck=ack)
s, j2, j, _ = req('/api/login', {'email': ad_em, 'password': ad_pw})
check('login with 2FA returns mfa_required + token (no session yet)',
      s == 200 and j.get('mfa_required') and j.get('mfa_token') and not j2, (s, j))
mt = j.get('mfa_token', '')
s, _, j, _ = req('/api/login/mfa', {'mfa_token': mt, 'code': wrong_code}, ck=j2)
check('MFA rejects wrong code', s == 401, (s, j))
s, mck, j, _ = req('/api/login/mfa', {'mfa_token': mt, 'code': totp(secret)}, ck=j2)
check('MFA accepts valid code and opens session', s == 200 and mck, (s, j))
s, _, j, _ = req('/api/login/mfa', {'mfa_token': mt, 'code': totp(secret)}, ck=mck)
check('MFA challenge single-use', s in (400, 401), (s, j))
# disable 2FA to leave account clean
c = conn(); c.execute("UPDATE users SET totp_secret='', totp_enabled=0 WHERE email=?", (ad_em,)); c.commit(); c.close()

# ---- cleanup ----
c = conn()
c.execute("DELETE FROM auth_events WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM password_resets WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'sec-%@dev.local')")
c.execute("DELETE FROM users WHERE email LIKE 'sec-%@dev.local'")
c.commit(); c.close()

print('\nALL PASS' if ok else '\nFAILURES PRESENT')
raise SystemExit(0 if ok else 1)
