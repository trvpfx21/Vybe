"""End-to-end test of admin-team management and customer/provider messaging (dev only)."""
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

def check(name, cond, extra=''):
    global ok
    print(('PASS  ' if cond else 'FAIL  ') + name + ('' if cond else ' -> ' + str(extra)))
    if not cond:
        ok = False

def login(em, pw):
    s, ck, j = req('/api/login', {'email': em, 'password': pw})
    assert s == 200, (s, j)
    return ck

def uid_of(em):
    con = sqlite3.connect(DB)
    row = con.execute('SELECT id FROM users WHERE email=?', (em,)).fetchone()
    con.close()
    return row[0] if row else None

def get_owner():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT id,email,is_owner,is_super,status FROM users WHERE role='admin' AND is_owner=1").fetchone()
    con.close()
    return dict(row) if row else None

con = sqlite3.connect(DB)
con.execute("DELETE FROM users WHERE email IN ('tmp-super@dev.local','tmp-clerk@dev.local')")
con.commit()
import server as S
cur = con.execute(
    "INSERT INTO users(name,email,role,password,status,is_super) VALUES(?,?,?,?,?,?)",
    ('Temp Super', 'tmp-super@dev.local', 'admin', S.pw_hash('TmpSuper!2026'), 'active', 1))
SID = cur.lastrowid
cur = con.execute(
    "INSERT INTO users(name,email,role,password,status,is_super) VALUES(?,?,?,?,?,?)",
    ('Temp Clerk', 'tmp-clerk@dev.local', 'admin', S.pw_hash('TmpClerk!2026'), 'active', 0))
CID = cur.lastrowid
con.commit()
con.close()

try:
    superck = login('tmp-super@dev.local', 'TmpSuper!2026')
    clerkck = login('tmp-clerk@dev.local', 'TmpClerk!2026')
    s, _, me = req('/api/me', ck=superck)
    check('super admin /api/me exposes is_super', s == 200 and me.get('user', {}).get('is_super') == 1, me)
    s, _, me = req('/api/me', ck=clerkck)
    check('regular admin /api/me is_super falsy', s == 200 and not me.get('user', {}).get('is_super'), me)

    # ---------- admin team list ---------- 
    s, _, admins = req('/api/admin/admins', ck=superck)
    check('super: can list admin team', s == 200 and any(a['email'] == 'tmp-super@dev.local' for a in admins), (s, admins)[:1])
    owner = get_owner()
    check('owner is marked as protected overall admin', owner and owner['is_owner'] == 1 and owner['is_super'] == 1 and owner['status'] == 'active', owner)
    if owner:
        s, _, j = req('/api/admin/admin/%d' % owner['id'], {'action': 'status', 'status': 'deleted'}, ck=superck)
        check('other overall admin cannot delete protected owner', s == 403, (s, j))
        con = sqlite3.connect(DB)
        try:
            con.execute('DELETE FROM users WHERE id=?', (owner['id'],))
            con.commit()
            blocked = False
        except sqlite3.IntegrityError:
            con.rollback()
            blocked = True
        finally:
            con.close()
        check('database trigger blocks direct owner deletion', blocked and get_owner() is not None)
    s, _, j = req('/api/admin/admins', ck=clerkck)
    check('regular admin: blocked from admin team list', s == 403, (s, j))

    # ---------- create admin ---------- 
    s, _, j = req('/api/admin/admins', {'name': 'Created Clerk', 'email': 'tmp-created@dev.local', 'password': 'Cobalt!River9X'}, ck=clerkck)
    check('regular admin: cannot create admins', s == 403, (s, j))
    s, _, j = req('/api/admin/admins', {'name': 'Created Clerk', 'email': 'tmp-created@dev.local', 'password': 'short'}, ck=superck)
    check('super: weak password rejected', s == 400, (s, j))
    s, _, j = req('/api/admin/admins', {'name': 'Created Clerk', 'email': 'tmp-created@dev.local', 'password': 'Cobalt!River9X'}, ck=superck)
    check('super: can create admin account', s == 201 and j.get('id'), (s, j))
    NEWID = j.get('id')
    createdck = login('tmp-created@dev.local', 'Cobalt!River9X')
    s, _, me = req('/api/me', ck=createdck)
    check('created admin can sign in with role admin', s == 200 and me.get('user', {}).get('role') == 'admin', me)
    s, _, stats = req('/api/stats', ck=createdck)
    check('created admin has full admin dashboard access', s == 200 and 'users' in stats, (s, list(stats) if isinstance(stats, dict) else stats))
    s, _, j = req('/api/admin/admins', ck=createdck)
    check('created (non-super) admin cannot list admin team', s == 403, (s, j))

    # ---------- manage admins ---------- 
    s, _, j = req('/api/admin/admin/%d' % NEWID, {'action': 'details', 'name': 'Renamed Clerk', 'email': 'tmp-renamed@dev.local'}, ck=clerkck)
    check('regular admin: cannot edit admins', s == 403, (s, j))
    s, _, j = req('/api/admin/admin/%d' % NEWID, {'action': 'details', 'name': 'Bad Email', 'email': 'not-an-email'}, ck=superck)
    check('super: malformed administrator email rejected', s == 400, (s, j))
    s, _, j = req('/api/admin/admin/%d' % NEWID, {'action': 'password', 'password': 'NewPass!2026'}, ck=superck)
    check('super: can reset admin password', s == 200, (s, j))
    login('tmp-renamed@dev.local', 'NewPass!2026') if False else None
    s, _, j = req('/api/admin/admin/%d' % NEWID, {'action': 'details', 'name': 'Renamed Clerk', 'email': 'tmp-renamed@dev.local'}, ck=superck)
    check('super: can edit admin details', s == 200, (s, j))
    renamedck = login('tmp-renamed@dev.local', 'NewPass!2026')
    check('renamed admin signs in with new email/password', bool(renamedck))
    s, _, j = req('/api/admin/admin/%d' % NEWID, {'action': 'super', 'is_super': True}, ck=superck)
    check('super: can grant overall-admin', s == 200, (s, j))
    s, _, j = req('/api/admin/admin/%d' % SID, {'action': 'super', 'is_super': False}, ck=superck)
    check('super: cannot remove own overall access (sole super demote blocked or self-guard)', s == 400, (s, j))
    s, _, j = req('/api/admin/admin/%d' % SID, {'action': 'status', 'status': 'suspended'}, ck=superck)
    check('super: cannot suspend own account', s == 400, (s, j))
    s, _, j = req('/api/admin/admin/%d' % SID, {'action': 'bogus'}, ck=superck)
    check('unknown admin action rejected', s == 404, (s, j))
    s, _, j = req('/api/admin/admin/999999', {'action': 'status', 'status': 'suspended'}, ck=superck)
    check('missing admin target 404', s == 404, (s, j))

    # ---------- messaging: customer <-> provider ---------- 
    # Use seeded customer1 (active) and an active provider with an approved, non-VIP profile.
    c1 = uid_of('customer1@nightlife.test')
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    prof = con.execute("SELECT p.id, p.provider_id, u.email FROM profiles p JOIN users u ON u.id=p.provider_id WHERE p.status='approved' AND p.is_vip=0 AND u.status='active' AND u.role='provider' LIMIT 1").fetchone()
    assert prof, 'expected an approved non-VIP provider profile in the demo data'
    pid = prof['id']
    p1 = prof['provider_id']
    p1_email = prof['email']
    con.execute('DELETE FROM messages WHERE customer_id=?', (c1,))
    con.commit(); con.close()
    c1ck = login('customer1@nightlife.test', 'EmpireDemo!2026')
    p1ck = login(p1_email, 'EmpireDemo!2026')

    s, _, j = req('/api/messages', {'profile_id': pid, 'body': 'Hello, are you available this weekend?'}, ck=c1ck)
    check('customer can message approved provider', s == 201, (s, j))
    s, _, j = req('/api/messages', {'profile_id': pid, 'body': 'x' * 2001}, ck=c1ck)
    check('over-long message rejected', s == 400, (s, j))
    s, _, inbox = req('/api/messages', ck=p1ck)
    check('provider inbox shows the conversation', any(t['customer_id'] == c1 and t['profile_id'] == pid for t in inbox), inbox[:1])
    s, _, thread = req('/api/messages?profile_id=%d' % pid, ck=p1ck)
    check('provider reads customer message', s == 200 and any(m['sender_id'] == c1 for m in thread.get('messages', [])), (s, thread))
    s, _, j = req('/api/messages', {'profile_id': pid, 'customer_id': c1, 'body': 'Yes! Saturday works for me.'}, ck=p1ck)
    check('provider can reply to customer conversation', s == 201, (s, j))
    s, _, thread = req('/api/messages?profile_id=%d' % pid, ck=c1ck)
    bodies = [m['body'] for m in thread.get('messages', [])]
    check('customer reads provider reply', s == 200 and any('Saturday' in b for b in bodies), (s, bodies))
    s, _, inbox = req('/api/messages', ck=c1ck)
    check('customer inbox shows last message', any(t['profile_id'] == pid and t['customer_id'] == c1 for t in inbox), inbox[:1])
    # provider cannot start a conversation with an arbitrary customer id
    c2 = uid_of('customer2@nightlife.test')
    s, _, j = req('/api/messages', {'profile_id': pid, 'customer_id': c2, 'body': 'unsolicited'}, ck=p1ck)
    check('provider cannot message customer who never wrote in', s == 404, (s, j))
    # anonymous cannot read threads
    s, _, j = req('/api/messages?profile_id=%d' % pid)
    check('anonymous cannot read thread', s == 403, (s, j))
    # suspended customer blocked from messaging
    con = sqlite3.connect(DB)
    con.execute("UPDATE users SET status='suspended' WHERE id=?", (c1,))
    con.commit(); con.close()
    s, _, j = req('/api/messages', {'profile_id': pid, 'body': 'still here?'}, ck=c1ck)
    check('suspended customer cannot message', s == 403, (s, j))
    con = sqlite3.connect(DB)
    con.execute("UPDATE users SET status='active' WHERE id=?", (c1,))
    con.commit(); con.close()
finally:
    con = sqlite3.connect(DB)
    c1 = uid_of('customer1@nightlife.test')
    if c1:
        con.execute('DELETE FROM messages WHERE customer_id=?', (c1,))
    con.execute("DELETE FROM audit WHERE admin_id IN (SELECT id FROM users WHERE email LIKE 'tmp-%@dev.local')")
    con.execute("DELETE FROM users WHERE email LIKE 'tmp-%@dev.local'")
    con.commit()
    con.close()

print('\nALL PASS' if ok else '\nFAILURES PRESENT')
raise SystemExit(0 if ok else 1)
