from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
import sqlite3, json, os, secrets, hashlib, hmac, time, re, mimetypes, struct, sys, getpass
import base64, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

ROOT=Path(__file__).parent.resolve()
_DATA_ENV=os.environ.get('VYBE_DATA_DIR','').strip()
DATA_DIR=Path(_DATA_ENV).expanduser().resolve() if _DATA_ENV else ROOT/'data'
DB=Path(os.environ.get('VYBE_DB',str(DATA_DIR/'nightlife.db'))).expanduser().resolve()
_MEDIA_ENV=os.environ.get('VYBE_MEDIA_DIR','').strip()
MEDIA_DIR=Path(_MEDIA_ENV).expanduser().resolve() if _MEDIA_ENV else (DATA_DIR/'media' if _DATA_ENV else ROOT/'media')
DB.parent.mkdir(parents=True,exist_ok=True)
COOKIE='ne_session'; IMAGE_TYPES={'image/jpeg','image/png','image/webp'}
SECURE_COOKIES=(os.environ.get('VYBE_SECURE','').strip()=='1' or os.environ.get('VYBE_ENV','').strip().lower()=='production')
DEV_RESET_LINK=os.environ.get('VYBE_DEV_RESET_LINK','').strip()=='1'
APP_ORIGIN=os.environ.get('VYBE_APP_ORIGIN','http://127.0.0.1:8004').rstrip('/')
SMTP_HOST=os.environ.get('VYBE_SMTP_HOST',''); SMTP_PORT=int(os.environ.get('VYBE_SMTP_PORT','587') or 587)
SMTP_USER=os.environ.get('VYBE_SMTP_USER',''); SMTP_PASS=os.environ.get('VYBE_SMTP_PASSWORD','')
SMTP_FROM=os.environ.get('VYBE_SMTP_FROM') or SMTP_USER or 'no-reply@vybe.local'
try: SCRYPT_N=2**max(14,min(17,int(os.environ.get('VYBE_SCRYPT_N','15'))))
except ValueError: SCRYPT_N=2**15
SCRYPT_R=8; SCRYPT_P=1
def _maxmem(n): return 128*SCRYPT_R*n*2+1024*1024
CSP="default-src 'self'; img-src 'self' https: data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
SESSION_IDLE={'admin':1800,'customer':28800,'provider':28800}
SESSION_ABS={'admin':43200,'customer':86400,'provider':86400}

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA secure_delete=ON'); return c
def rows(q,args=()):
    with connect() as c: return [dict(x) for x in c.execute(q,args).fetchall()]
def one(q,args=()):
    a=rows(q,args); return a[0] if a else None
def setting_json(key,default):
    raw=one('SELECT value FROM settings WHERE key=?',(key,))
    try:return json.loads(raw['value']) if raw else default
    except (ValueError,TypeError):return default
def valid_catalog(values,kind):
    if not isinstance(values,list):return False
    limit=500 if kind=='services' else 1000
    clean=[str(v).strip() for v in values]
    if len(clean)>limit:return False
    if not all(v and len(v)<=160 for v in clean):return False
    return len({v.casefold() for v in clean})==len(clean)
def normalize_service_prices(values):
    try:items=json.loads(values or '[]') if isinstance(values,str) else values
    except (ValueError,TypeError):items=[]
    normalized=[]
    for item in items if isinstance(items,list) else []:
        if not isinstance(item,dict) or not item.get('name'):continue
        try:price=int(float(item.get('price',item.get('price_min',0)) or 0))
        except (TypeError,ValueError,OverflowError):price=0
        normalized.append({'name':str(item['name']),'price':max(0,min(price,100000000))})
    return normalized
def init():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,phone TEXT DEFAULT '',role TEXT NOT NULL CHECK(role IN ('admin','provider','customer')),password TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',avatar TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE REFERENCES users(id),whatsapp TEXT DEFAULT '',location TEXT DEFAULT '',description TEXT DEFAULT '',status TEXT DEFAULT 'pending_review',notes TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY,provider_id INTEGER REFERENCES users(id),title TEXT,category TEXT,location TEXT,description TEXT,image TEXT DEFAULT '',status TEXT DEFAULT 'draft',feedback TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY,provider_id INTEGER UNIQUE REFERENCES users(id),display_name TEXT NOT NULL,bio TEXT DEFAULT '',location TEXT DEFAULT '',categories TEXT DEFAULT '[]',photos TEXT DEFAULT '[]',videos TEXT DEFAULT '[]',services TEXT DEFAULT '[]',service_mode TEXT NOT NULL DEFAULT 'both',is_vip INTEGER DEFAULT 0,contact_phone TEXT DEFAULT '',contact_whatsapp TEXT DEFAULT '',show_phone INTEGER DEFAULT 0,show_whatsapp INTEGER DEFAULT 0,verified INTEGER DEFAULT 0,status TEXT DEFAULT 'pending',feedback TEXT DEFAULT '',updated_at TEXT DEFAULT CURRENT_TIMESTAMP,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY,reporter_id INTEGER REFERENCES users(id),listing_id INTEGER REFERENCES listings(id),profile_id INTEGER REFERENCES profiles(id),reason TEXT,status TEXT DEFAULT 'open',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,profile_id INTEGER NOT NULL REFERENCES profiles(id),customer_id INTEGER NOT NULL REFERENCES users(id),sender_id INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY,profile_id INTEGER NOT NULL REFERENCES profiles(id),customer_id INTEGER NOT NULL REFERENCES users(id),rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),body TEXT DEFAULT '',status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(profile_id,customer_id));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,admin_id INTEGER,action TEXT,target_type TEXT,target_id INTEGER,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS vip_memberships(id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','active','suspended','expired')),started_at TEXT,expires_at TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS vip_membership_history(id INTEGER PRIMARY KEY,membership_id INTEGER REFERENCES vip_memberships(id),admin_id INTEGER,action TEXT,status TEXT,expires_at TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS saved_profiles(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),profile_id INTEGER NOT NULL REFERENCES profiles(id),created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,profile_id));
        CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),token_hash TEXT UNIQUE NOT NULL,ip TEXT DEFAULT '',user_agent TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,expires_at INTEGER NOT NULL,revoked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS password_resets(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),token_hash TEXT UNIQUE NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,expires_at INTEGER NOT NULL,used INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS auth_events(id INTEGER PRIMARY KEY,user_id INTEGER,event TEXT NOT NULL,ip TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS mfa_challenges(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),token_hash TEXT UNIQUE NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,expires_at INTEGER NOT NULL,used INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);
        CREATE INDEX IF NOT EXISTS idx_auth_events ON auth_events(user_id,created_at);
        ''')
        c.execute("INSERT OR IGNORE INTO settings VALUES('platform_name','VYBE')")
        cols=[r['name'] for r in c.execute('PRAGMA table_info(reports)')]
        if 'profile_id' not in cols:c.execute('ALTER TABLE reports ADD COLUMN profile_id INTEGER REFERENCES profiles(id)')
        user_cols=[r['name'] for r in c.execute('PRAGMA table_info(users)')]
        if 'avatar' not in user_cols:c.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")
        if 'is_vip' not in user_cols:c.execute('ALTER TABLE users ADD COLUMN is_vip INTEGER DEFAULT 0')
        if 'is_super' not in user_cols:c.execute('ALTER TABLE users ADD COLUMN is_super INTEGER DEFAULT 0')
        if 'is_owner' not in user_cols:c.execute('ALTER TABLE users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0')
        if 'totp_secret' not in user_cols:c.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''")
        if 'totp_enabled' not in user_cols:c.execute('ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0')
        if not c.execute("SELECT 1 FROM users WHERE role='admin' AND is_super=1 AND status!='deleted'").fetchone():c.execute("UPDATE users SET is_super=1 WHERE id=(SELECT MIN(id) FROM users WHERE role='admin' AND status!='deleted')")
        if not c.execute("SELECT 1 FROM users WHERE role='admin' AND is_owner=1 AND status!='deleted'").fetchone():
            c.execute("UPDATE users SET is_owner=0 WHERE role='admin'")
            c.execute("UPDATE users SET is_owner=1,is_super=1 WHERE id=(SELECT id FROM users WHERE role='admin' AND status='active' ORDER BY id LIMIT 1)")
        c.execute("UPDATE users SET role='admin',status='active',is_super=1,is_owner=1 WHERE role='admin' AND is_owner=1")
        c.executescript('''
        CREATE TRIGGER IF NOT EXISTS protect_vybe_owner_delete
        BEFORE DELETE ON users WHEN OLD.is_owner=1
        BEGIN SELECT RAISE(ABORT,'protected owner account cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS protect_vybe_owner_identity
        BEFORE UPDATE OF role,status,is_super,is_owner ON users
        WHEN OLD.is_owner=1 AND (NEW.role!='admin' OR NEW.status!='active' OR NEW.is_super!=1 OR NEW.is_owner!=1)
        BEGIN SELECT RAISE(ABORT,'protected owner account must remain active overall admin'); END;
        ''')
        profile_cols=[r['name'] for r in c.execute('PRAGMA table_info(profiles)')]
        if 'videos' not in profile_cols:c.execute("ALTER TABLE profiles ADD COLUMN videos TEXT DEFAULT '[]'")
        if 'services' not in profile_cols:c.execute("ALTER TABLE profiles ADD COLUMN services TEXT DEFAULT '[]'")
        if 'is_vip' not in profile_cols:c.execute('ALTER TABLE profiles ADD COLUMN is_vip INTEGER DEFAULT 0')
        if 'service_mode' not in profile_cols:c.execute("ALTER TABLE profiles ADD COLUMN service_mode TEXT NOT NULL DEFAULT 'both'")
        defaults={'service_catalog':['Hair styling','Photography','Tutoring','Fitness coaching','Home cleaning','Event planning','Home repairs','Graphic design','Music lessons','Catering','Consulting','Other general service'],'locations':['Kampala','Entebbe','Jinja'],'vip_price_ugx':'150000','vip_duration_days':'30'}
        for key,value in defaults.items():c.execute('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)',(key,json.dumps(value) if isinstance(value,list) else value))

def pw_hash(pw):
    salt=secrets.token_bytes(16); dk=hashlib.scrypt(pw.encode(),salt=salt,n=SCRYPT_N,r=SCRYPT_R,p=SCRYPT_P,maxmem=_maxmem(SCRYPT_N))
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$'+base64.b64encode(salt).decode()+'$'+base64.b64encode(dk).decode()
def pw_needs_rehash(stored):
    try:return not str(stored).startswith(f'scrypt${SCRYPT_N}$')
    except Exception:return True
DUMMY_HASH=None
def _dummy_hash():
    global DUMMY_HASH
    if DUMMY_HASH is None: DUMMY_HASH=pw_hash(secrets.token_urlsafe(16))
    return DUMMY_HASH
def verify(pw,stored):
    try:
        stored=str(stored)
        if stored.startswith('scrypt$'):
            _,n,r,p,sb,db=stored.split('$'); n=int(n); r=int(r); p=int(p)
            dk=hashlib.scrypt(pw.encode(),salt=base64.b64decode(sb),n=n,r=r,p=p,maxmem=_maxmem(n))
            return hmac.compare_digest(base64.b64encode(dk).decode(),db)
        s,d=stored.split(':'); return hmac.compare_digest(hashlib.scrypt(pw.encode(),salt=bytes.fromhex(s),n=2**14,r=8,p=1,maxmem=64*1024*1024).hex(),d)
    except Exception: return False
COMMON_PASSWORDS={'password','12345678','qwerty123','letmein1','iloveyou','admin123','welcome1','password1','abc12345','passw0rd','football','monkey123','dragon123','sunshine','princess','trustno1','baseball','superman','starwars','qwerty1234','vybe1234','nightlife'}
EMAIL_RE=re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]{2,}")
def password_issues(pw,role='customer',email='',name=''):
    issues=[]; pw=str(pw or ''); minlen=12 if role=='admin' else 6
    if len(pw)<minlen: issues.append(f'at least {minlen} characters')
    if len(pw)>200: issues.append('fewer than 200 characters')
    if role!='admin': return issues
    classes=sum(bool(re.search(pat,pw)) for pat in (r'[a-z]',r'[A-Z]',r'\d',r'[^A-Za-z0-9]'))
    need=3 if role=='admin' else 2
    if classes<need: issues.append('a mix of lower-case, upper-case, numbers and symbols')
    if pw.lower() in COMMON_PASSWORDS or (pw and len(set(pw.lower()))<=2): issues.append('not a common or repeated password')
    el=(email.split('@')[0] or '').lower()
    if len(el)>=3 and el in pw.lower(): issues.append('not based on your email address')
    parts=(name or '').split(); nl=parts[0].lower() if parts else ''
    if len(nl)>=3 and nl in pw.lower(): issues.append('not based on your name')
    return issues
def sha256_hex(s):return hashlib.sha256(str(s).encode()).hexdigest()
_RATE={}
def _rate_rec(bucket,ident):
    return _RATE.setdefault(bucket+'|'+ident,{'hits':[],'locked_until':0.0})
def rate_check(bucket,ident,limit,window):
    now=time.time(); rec=_RATE.get(bucket+'|'+ident)
    if not rec:return None
    if rec['locked_until']>now:return max(1,int(rec['locked_until']-now))
    rec['hits']=[t for t in rec['hits'] if now-t<window]
    if len(rec['hits'])>=limit:return max(1,window-int(now-rec['hits'][0]))
    return None
def rate_hit(bucket,ident,limit,window,lock):
    now=time.time(); rec=_rate_rec(bucket,ident)
    rec['hits']=[t for t in rec['hits'] if now-t<window]; rec['hits'].append(now)
    if len(rec['hits'])>=limit:rec['locked_until']=max(rec['locked_until'],now+lock)
def rate_clear(bucket,ident):_RATE.pop(bucket+'|'+ident,None)
def totp_secret_new():return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
def totp_code(secret,offset=0):
    key=base64.b32decode(secret.upper()+'='*((8-len(secret)%8)%8))
    counter=int(time.time()//30)+offset
    h=hmac.new(key,counter.to_bytes(8,'big'),hashlib.sha1).digest()
    o=h[-1]&0x0f
    return f'{(struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%10**6:06d}'
def totp_verify(secret,code):
    code=str(code or '').strip().replace(' ','')
    return bool(re.fullmatch(r'\d{6}',code)) and any(hmac.compare_digest(totp_code(secret,off),code) for off in (-1,0,1))
def vip_expiry_default(days=30):
    try:days=max(1,min(3650,int(days or 30)))
    except (TypeError,ValueError):days=30
    return (datetime.now(timezone.utc)+timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
def vip_state(uid):
    m=one('SELECT * FROM vip_memberships WHERE user_id=?',(uid,))
    if not m:return {'status':'none','expires_at':None}
    st=m['status'];exp=m['expires_at']
    if st=='active' and exp:
        try:expired=datetime.strptime(str(exp),'%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)<=datetime.now(timezone.utc)
        except ValueError:expired=False
        if expired:
            with connect() as c:
                c.execute("UPDATE vip_memberships SET status='expired',updated_at=CURRENT_TIMESTAMP WHERE id=?",(m['id'],))
                c.execute('UPDATE users SET is_vip=0 WHERE id=?',(uid,))
                c.execute('INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?,?, ?,?)',(m['id'],None,'expired','expired',exp))
            st='expired'
    return {'status':st,'expires_at':exp}
def vip_client(uid):
    if not uid:return False
    return vip_state(uid)['status']=='active'
def audit(uid,action,typ,tid,detail=''):
    with connect() as c: c.execute('INSERT INTO audit(admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)',(uid,action,typ,tid,detail))
def save_image(value):
    if value.startswith('data:'):
        match=re.fullmatch(r'data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)',value)
        if not match:raise ValueError('Images must be PNG, JPEG or WebP')
        blob=base64.b64decode(match.group(2),validate=True)
        if len(blob)>5*1024*1024:raise ValueError('Images must be 5 MB or smaller')
        kind=match.group(1)
        if kind=='image/png' and not blob.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('Image contents do not match the PNG file type')
        if kind=='image/jpeg' and not blob.startswith(b'\xff\xd8\xff'):raise ValueError('Image contents do not match the JPEG file type')
        if kind=='image/webp' and not (blob.startswith(b'RIFF') and blob[8:12]==b'WEBP'):raise ValueError('Image contents do not match the WebP file type')
        ext={'image/jpeg':'jpg','image/png':'png','image/webp':'webp'}[match.group(1)];name=secrets.token_hex(16)+'.'+ext;MEDIA_DIR.mkdir(parents=True,exist_ok=True);(MEDIA_DIR/name).write_bytes(blob);return '/media/'+name
    if value.startswith('/media/') and re.fullmatch(r'/media/[0-9a-f]{32}\.(?:jpg|png|webp)',value) and (ROOT/value.lstrip('/')).is_file():return value
    if value and (not value.startswith('https://') or len(value)>1000):raise ValueError('Image URLs must use HTTPS')
    return value

def save_video(value):
    match=re.fullmatch(r'data:(video/(?:mp4|webm|quicktime));base64,([A-Za-z0-9+/=]+)',value)
    if not match:raise ValueError('Videos must be MP4, WebM or MOV')
    blob=base64.b64decode(match.group(2),validate=True)
    if len(blob)>20*1024*1024:raise ValueError('Videos must be 20 MB or smaller')
    kind=match.group(1)
    if kind=='video/webm' and not blob.startswith(b'\x1a\x45\xdf\xa3'):raise ValueError('Video contents do not match WebM')
    if kind in ('video/mp4','video/quicktime') and (len(blob)<12 or blob[4:8]!=b'ftyp'):raise ValueError('Video contents do not match MP4/MOV')
    ext={'video/mp4':'mp4','video/webm':'webm','video/quicktime':'mov'}[kind];name=secrets.token_hex(16)+'.'+ext;MEDIA_DIR.mkdir(parents=True,exist_ok=True);(MEDIA_DIR/name).write_bytes(blob);return '/media/'+name

class App(SimpleHTTPRequestHandler):
    def log_message(self,*args): pass
    def client_ip(self): return self.client_address[0] if self.client_address else ''
    def respond(self,data,code=200,cookie=None):
        out=json.dumps(data,default=str).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out))); self.send_header('Cache-Control','no-store'); self._sec_headers()
        if cookie:self.set_cookie(*cookie)
        self.end_headers(); self.wfile.write(out)
    def set_cookie(self,name,value,max_age):
        attrs=f'{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}'
        if SECURE_COOKIES:attrs+='; Secure'
        self.send_header('Set-Cookie',attrs)
    def _sec_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','strict-origin-when-cross-origin')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',CSP)
        if SECURE_COOKIES:self.send_header('Strict-Transport-Security','max-age=31536000; includeSubDomains')
    def request_origin(self):
        o=self.headers.get('Origin')
        if o and o!='null':return o
        ref=self.headers.get('Referer','')
        try:return urlparse(ref)._replace(path='',params='',query='',fragment='').geturl() if ref else ''
        except Exception:return ''
    def same_origin_request(self):
        origin=self.request_origin()
        if not origin:return True
        host=self.headers.get('Host','')
        return origin.rstrip('/')==f'http://{host}' or origin.rstrip('/')==f'https://{host}'
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if n>130_000_000: raise ValueError('Request body too large')
        return json.loads(self.rfile.read(n) or b'{}')
    def get_cookie(self):
        raw=self.headers.get('Cookie','')
        if COOKIE+'=' not in raw:return ''
        return raw.split(COOKIE+'=')[-1].split(';')[0].strip()
    def create_session(self,uid,role):
        token=secrets.token_urlsafe(32)
        now=int(time.time()); exp=now+SESSION_ABS.get(role,86400)
        ua=(self.headers.get('User-Agent','') or '')[:300]
        with connect() as c:
            c.execute('DELETE FROM sessions WHERE expires_at<? OR revoked=1',(now-86400,))
            c.execute('INSERT INTO sessions(user_id,token_hash,ip,user_agent,expires_at) VALUES(?,?,?,?,?)',(uid,sha256_hex(token),self.client_ip(),ua,exp))
        return (COOKIE,token,SESSION_ABS.get(role,86400))
    def current(self):
        token=self.get_cookie()
        if not token or len(token)>200:return None
        now=int(time.time())
        s=one('SELECT * FROM sessions WHERE token_hash=? AND revoked=0',(sha256_hex(token),))
        if not s:return None
        if s['expires_at']<now:
            with connect() as c:c.execute('UPDATE sessions SET revoked=1 WHERE id=?',(s['id'],))
            return None
        u=one("SELECT id,name,email,role,status,is_vip,is_super,is_owner,totp_enabled FROM users WHERE id=? AND status!='deleted'",(s['user_id'],))
        if not u:
            with connect() as c:c.execute('UPDATE sessions SET revoked=1 WHERE id=?',(s['id'],))
            return None
        idle=SESSION_IDLE.get(u['role'],28800)
        try:last=int(datetime.strptime(str(s['last_seen_at']),'%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
        except ValueError:last=now
        if now-last>idle:
            with connect() as c:c.execute('UPDATE sessions SET revoked=1 WHERE id=?',(s['id'],))
            return None
        if now-last>60:
            with connect() as c:c.execute('UPDATE sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?',(s['id'],))
        return u
    def revoke_sessions(self,uid,keep_current=False):
        now=int(time.time())
        with connect() as c:
            if keep_current:
                th=sha256_hex(self.get_cookie()) if self.get_cookie() else '__none__'
                c.execute('UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash!=?',(uid,th))
            else:c.execute('UPDATE sessions SET revoked=1 WHERE user_id=?',(uid,))
    def auth_event(self,uid,event):
        try:
            with connect() as c:c.execute('INSERT INTO auth_events(user_id,event,ip) VALUES(?,?,?)',(uid if uid else None,event,self.client_ip()))
        except sqlite3.Error:pass
    def _send_email(self,to,subject,body):
        if not SMTP_HOST or not EMAIL_RE.fullmatch(str(to)):return False
        try:
            msg=EmailMessage(); msg['Subject']=subject; msg['From']=SMTP_FROM; msg['To']=to; msg.set_content(body)
            with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=10) as s:
                s.ehlo()
                try:s.starttls(); s.ehlo()
                except smtplib.SMTPException:pass
                if SMTP_USER:s.login(SMTP_USER,SMTP_PASS)
                s.send_message(msg)
            return True
        except Exception:return False
    def admin(self):
        u=self.current()
        if not u or u['role']!='admin': self.respond({'error':'Administrator access required'},403); return None
        return u
    def superadmin(self):
        u=self.current()
        if not u or u['role']!='admin' or not u.get('is_super'): self.respond({'error':'Overall administrator access required'},403); return None
        return u
    def do_GET(self):
        path=urlparse(self.path).path
        if path.startswith('/api/'):
            u=self.current()
            if path=='/api/me': return self.respond({'user':u,'vip':vip_state(u['id']) if u and u['role']=='customer' else None})
            if path=='/api/config':return self.respond({'services':setting_json('service_catalog',[]),'locations':setting_json('locations',[]),'vip':{'price':setting_json('vip_price_ugx','150000'),'days':setting_json('vip_duration_days','30')}})
            if path=='/api/profiles':
                if u and u['role']=='provider':return self.respond({'error':'Provider accounts can only access their own profile and client conversations'},403)
                vip_ok=bool(u and (u['role']=='admin' or (u['role']=='customer' and vip_client(u['id']))))
                profiles=rows("SELECT p.id,p.display_name,p.bio,p.location,p.categories,p.photos,p.videos,p.services,p.service_mode,p.is_vip,p.verified,p.contact_phone,p.contact_whatsapp,p.show_phone,p.show_whatsapp,COALESCE(AVG(r.rating),0) rating,COUNT(r.id) rating_count FROM profiles p JOIN users u ON u.id=p.provider_id LEFT JOIN reviews r ON r.profile_id=p.id AND r.status='approved' WHERE p.status='approved' AND u.status='active' AND (p.is_vip=0 OR ?) GROUP BY p.id ORDER BY p.is_vip DESC,p.verified DESC,p.created_at DESC",(int(vip_ok),))
                may_see_contacts=bool(u and u['role']=='customer' and u['status']=='active')
                for p in profiles:
                    p['categories']=json.loads(p['categories'] or '[]');p['photos']=json.loads(p['photos'] or '[]');p['videos']=json.loads(p['videos'] or '[]');p['services']=normalize_service_prices(p['services']);p['is_vip']=bool(p['is_vip']);p['rating']=round(p['rating'],1)
                    p.pop('show_phone',None);p.pop('show_whatsapp',None)
                    if not may_see_contacts:p.pop('contact_phone',None);p.pop('contact_whatsapp',None)
                return self.respond(profiles)
            if re.fullmatch(r'/api/profiles/\d+',path):
                pid=int(path.rsplit('/',1)[1]);p=one("SELECT p.id,p.provider_id,p.display_name,p.bio,p.location,p.categories,p.photos,p.videos,p.services,p.service_mode,p.is_vip,p.verified,p.contact_phone,p.contact_whatsapp,p.show_phone,p.show_whatsapp,COALESCE((SELECT ROUND(AVG(rating),1) FROM reviews r WHERE r.profile_id=p.id AND r.status='approved'),0) rating,(SELECT COUNT(*) FROM reviews r WHERE r.profile_id=p.id AND r.status='approved') rating_count FROM profiles p JOIN users u ON u.id=p.provider_id WHERE p.id=? AND p.status='approved' AND u.status='active'",(pid,))
                if not p:return self.respond({'error':'Profile not found'},404)
                if p['is_vip'] and not bool(u and (u['role']=='admin' or (u['role']=='customer' and vip_client(u['id'])) or (u['role']=='provider' and u['id']==p['provider_id']))):return self.respond({'error':'VIP membership is required to view this profile','code':'vip_required'},403)
                if u and u['role']=='provider' and u['id']!=p['provider_id']:return self.respond({'error':'Provider accounts can only view their own profile'},403)
                may_see_contacts=bool(u and u['role']=='customer' and u['status']=='active')
                p['categories']=json.loads(p['categories'] or '[]');p['photos']=json.loads(p['photos'] or '[]');p['videos']=json.loads(p['videos'] or '[]');p['services']=normalize_service_prices(p['services']);p['is_vip']=bool(p['is_vip']);p['verified']=bool(p['verified']);p['reviews']=rows("SELECT r.rating,r.body,r.created_at,u.name customer_name FROM reviews r JOIN users u ON u.id=r.customer_id WHERE r.profile_id=? AND r.status='approved' ORDER BY r.created_at DESC LIMIT 20",(pid,))
                p.pop('provider_id',None)
                p.pop('show_phone',None);p.pop('show_whatsapp',None)
                if not may_see_contacts:p.pop('contact_phone',None);p.pop('contact_whatsapp',None)
                return self.respond(p)
            if path=='/api/stats':
                if not self.admin(): return
                keys=['users','customers','providers','pending_applications','active_providers','unpublished_profiles','approved_profiles','open_reports','pending_reviews','vip_profiles','vip_clients']
                qs=["SELECT count(*) n FROM users WHERE status!='deleted'","SELECT count(*) n FROM users WHERE role='customer' AND status!='deleted'","SELECT count(*) n FROM users WHERE role='provider' AND status!='deleted'","SELECT count(*) n FROM applications WHERE status IN ('pending_review','contact_required')","SELECT count(*) n FROM users WHERE role='provider' AND status='active'","SELECT count(*) n FROM profiles WHERE status IN ('pending','changes_requested','draft')","SELECT count(*) n FROM profiles WHERE status='approved'","SELECT count(*) n FROM reports WHERE status='open' AND profile_id IS NOT NULL","SELECT count(*) n FROM reviews WHERE status='pending'","SELECT count(*) n FROM profiles WHERE is_vip=1 AND status='approved'","SELECT count(*) n FROM users WHERE role='customer' AND status='active' AND is_vip=1"]
                return self.respond({k:one(q)['n'] for k,q in zip(keys,qs)})
            if path.startswith('/api/admin/'):
                if not self.admin(): return
                key=path.rsplit('/',1)[-1]
                sql={'applications':"SELECT a.*,u.name,u.email,u.phone,p.id profile_id,p.status profile_status FROM applications a JOIN users u ON u.id=a.user_id LEFT JOIN profiles p ON p.provider_id=u.id WHERE u.status!='deleted' ORDER BY a.created_at DESC",'providers':"SELECT u.id,u.name,u.email,u.phone,u.status,a.location,p.is_vip,p.status profile_status FROM users u LEFT JOIN applications a ON a.user_id=u.id LEFT JOIN profiles p ON p.provider_id=u.id WHERE u.role='provider' AND u.status!='deleted' ORDER BY u.created_at DESC",'customers':"SELECT u.id,u.name,u.email,u.phone,u.status,u.is_vip,u.created_at,m.status vip_status,m.expires_at vip_expires FROM users u LEFT JOIN vip_memberships m ON m.user_id=u.id WHERE u.role='customer' AND u.status!='deleted' ORDER BY u.created_at DESC",'profiles':"SELECT p.*,u.email,u.phone provider_phone,u.name account_name FROM profiles p JOIN users u ON u.id=p.provider_id WHERE u.status!='deleted' ORDER BY p.created_at DESC",'reports':"SELECT r.*,u.name reporter,p.display_name profile_name FROM reports r JOIN users u ON u.id=r.reporter_id JOIN profiles p ON p.id=r.profile_id ORDER BY r.created_at DESC",'audit':"SELECT a.*,u.name admin_name FROM audit a LEFT JOIN users u ON u.id=a.admin_id ORDER BY a.id DESC LIMIT 100",'reviews':"SELECT r.*,u.name customer_name,p.display_name FROM reviews r JOIN users u ON u.id=r.customer_id JOIN profiles p ON p.id=r.profile_id ORDER BY r.created_at DESC"}
                if key in sql:return self.respond(rows(sql[key]))
                if key=='admins':
                    if not u.get('is_super'):return self.respond({'error':'Overall administrator access required'},403)
                    return self.respond(rows("SELECT id,name,email,status,is_super,is_owner,created_at FROM users WHERE role='admin' AND status!='deleted' ORDER BY is_owner DESC,is_super DESC,created_at ASC"))
                if key=='catalog':return self.respond({'services':setting_json('service_catalog',[]),'locations':setting_json('locations',[])})
                if key=='vip':return self.respond({'profiles':rows("SELECT p.id,p.display_name,p.location,p.is_vip,p.status,p.photos,p.bio,p.updated_at,u.name account_name,u.email FROM profiles p JOIN users u ON u.id=p.provider_id WHERE p.status='approved' AND u.status='active' ORDER BY p.is_vip DESC,p.created_at DESC"),'members':rows("SELECT m.id,m.user_id,m.status,m.started_at,m.expires_at,m.updated_at,u.name,u.email,u.status account_status FROM vip_memberships m JOIN users u ON u.id=m.user_id ORDER BY m.updated_at DESC"),'history':rows("SELECT h.*,u.name member_name,a.name admin_name FROM vip_membership_history h LEFT JOIN vip_memberships m ON m.id=h.membership_id LEFT JOIN users u ON u.id=m.user_id LEFT JOIN users a ON a.id=h.admin_id ORDER BY h.id DESC LIMIT 100")})
            if path=='/api/provider':
                if not u or u['role']!='provider':return self.respond({'error':'Provider login required'},403)
                profile=one('SELECT * FROM profiles WHERE provider_id=?',(u['id'],))
                if profile:profile['categories']=json.loads(profile['categories'] or '[]');profile['photos']=json.loads(profile['photos'] or '[]');profile['videos']=json.loads(profile['videos'] or '[]');profile['services']=normalize_service_prices(profile['services'])
                rating=one("SELECT COALESCE(ROUND(AVG(rating),1),0) rating,COUNT(*) count FROM reviews WHERE profile_id=? AND status='approved'",(profile['id'],)) if profile else {'rating':0,'count':0}
                return self.respond({'application':one('SELECT * FROM applications WHERE user_id=?',(u['id'],)),'rating':rating,'reviews':rows("SELECT r.rating,r.body,r.status,r.created_at,u.name customer_name FROM reviews r JOIN users u ON u.id=r.customer_id WHERE r.profile_id=? ORDER BY r.created_at DESC LIMIT 50",(profile['id'],)) if profile else [],'config':{'services':setting_json('service_catalog',[]),'locations':setting_json('locations',[]),},'profile':profile})
            if path=='/api/customer':
                if not u or u['role']!='customer':return self.respond({'error':'Customer login required'},403)
                return self.respond({'user':one('SELECT id,name,email,phone,role,status FROM users WHERE id=?',(u['id'],)),'reports':rows('SELECT * FROM reports WHERE reporter_id=? ORDER BY id DESC',(u['id'],))})
            if path=='/api/customer/reports':
                if not u or u['role']!='customer':return self.respond({'error':'Customer login required'},403)
                return self.respond(rows('SELECT * FROM reports WHERE reporter_id=?',(u['id'],)))
            if path=='/api/vip':
                if not u or u['role']!='customer':return self.respond({'error':'Customer login required'},403)
                return self.respond({'membership':vip_state(u['id'])})
            if path=='/api/saved':
                if not u or u['role']!='customer':return self.respond({'error':'Customer login required'},403)
                st=vip_state(u['id'])
                saved=rows('SELECT s.profile_id,s.created_at,p.display_name,p.location,p.bio,p.photos,p.is_vip,COALESCE((SELECT ROUND(AVG(r.rating),1) FROM reviews r WHERE r.profile_id=p.id AND r.status=\'approved\'),0) rating,(SELECT COUNT(*) FROM reviews r WHERE r.profile_id=p.id AND r.status=\'approved\') rating_count FROM saved_profiles s JOIN profiles p ON p.id=s.profile_id JOIN users pu ON pu.id=p.provider_id WHERE s.user_id=? AND p.status=? AND pu.status=? ORDER BY s.id DESC',(u['id'],'approved','active'))
                if not (st['status']=='active' or u['role']=='admin'):saved=[x for x in saved if not x['is_vip']]
                for x in saved:x['photos']=json.loads(x['photos'] or '[]');x['is_vip']=bool(x['is_vip'])
                return self.respond(saved)
            if path=='/api/messages':
                if not u or u['role'] not in ('customer','provider') or u['status']!='active':return self.respond({'error':'An active customer or provider account is required'},403)
                profile_id=urlparse(self.path).query
                if profile_id.startswith('profile_id='):
                    try:pid=int(profile_id.split('=',1)[1])
                    except ValueError:return self.respond({'error':'Invalid profile'},400)
                    prof=one('SELECT id,provider_id,display_name,status,is_vip FROM profiles WHERE id=?',(pid,))
                    if not prof:return self.respond({'error':'Profile not found'},404)
                    if u['role']=='provider' and prof['provider_id']!=u['id']:return self.respond({'error':'This conversation is not yours'},403)
                    if u['role']=='customer' and prof['status']!='approved':return self.respond({'error':'This profile is not available for messages'},404)
                    if prof['is_vip'] and u['role']=='customer' and not vip_client(u['id']):return self.respond({'error':'VIP membership is required to contact this provider','code':'vip_required'},403)
                    client_id=u['id'] if u['role']=='customer' else one('SELECT customer_id FROM messages WHERE profile_id=? AND sender_id!=? ORDER BY id DESC LIMIT 1',(pid,u['id']))['customer_id'] if one('SELECT 1 FROM messages WHERE profile_id=? AND sender_id!=? LIMIT 1',(pid,u['id'])) else -1
                    if prof['is_vip'] and u['role']=='provider' and not vip_client(client_id):return self.respond({'error':'This VIP conversation is limited to active VIP members'},403)
                    msgs=rows('SELECT m.id,m.sender_id,m.body,m.created_at,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.profile_id=? AND m.customer_id=? ORDER BY m.id',(pid,client_id))
                    return self.respond({'profile':prof['display_name'],'messages':msgs})
                inbox=rows("SELECT m.profile_id,m.customer_id,p.display_name,cu.name customer_name,m.body,m.created_at FROM messages m JOIN profiles p ON p.id=m.profile_id JOIN users cu ON cu.id=m.customer_id WHERE m.id=(SELECT MAX(m2.id) FROM messages m2 WHERE m2.profile_id=m.profile_id AND m2.customer_id=m.customer_id) AND (m.customer_id=? OR p.provider_id=?) AND (p.is_vip=0 OR cu.is_vip=1) ORDER BY m.id DESC",(u['id'],u['id']))
                return self.respond(inbox)
            return self.respond({'error':'Not found'},404)
        if path in ('/','/admin','/reset','/login','/account'):
            file=ROOT/'index.html'
        elif path in ('/app.js','/style.css'):
            file=ROOT/path.lstrip('/')
        elif re.fullmatch(r'/media/[0-9a-f]{32}\.(?:jpg|png|webp|mp4|webm|mov)',path):
            file=MEDIA_DIR/path.rsplit('/',1)[-1]
        else:
            self.send_error(404); return
        if not file.is_file(): self.send_error(404); return
        b=file.read_bytes(); self.send_response(200); self.send_header('Content-Type',mimetypes.guess_type(file.name)[0] or 'application/octet-stream'); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-cache'); self._sec_headers(); self.end_headers(); self.wfile.write(b)
    def do_HEAD(self):
        self.send_error(405,'HEAD requests are not supported')
    def do_POST(self):
        path=urlparse(self.path).path
        if path.startswith('/api/') and not self.same_origin_request():return self.respond({'error':'Cross-origin request blocked'},403)
        try: d=self.body()
        except (ValueError,json.JSONDecodeError): return self.respond({'error':'Request body is too large or invalid JSON'},413)
        u=self.current()
        try:
            if path=='/api/register':
                role=d.get('role','customer'); email=str(d.get('email','')).strip().lower(); password=str(d.get('password','')); name=str(d.get('name','')).strip()
                if role not in ('customer','provider') or not name or len(name)>100 or not EMAIL_RE.fullmatch(email) or len(email)>254 or d.get('passwordConfirm')!=password: return self.respond({'error':'Enter your name, a valid email, and matching passwords of at least 6 characters'},400)
                issues=password_issues(password,'customer',email,name)
                if issues:return self.respond({'error':'Choose a stronger password: use '+', '.join(issues)+'.'},400)
                wait=rate_check('reg_ip',self.client_ip(),5,3600)
                if wait:return self.respond({'error':'Too many accounts created from this device. Try again later.'},429)
                with connect() as c:
                    cur=c.execute('INSERT INTO users(name,email,phone,role,password,status) VALUES(?,?,?,?,?,?)',(name,email,str(d.get('phone',''))[:50],role,pw_hash(password),'pending' if role=='provider' else 'active')); uid=cur.lastrowid
                    if role=='provider': c.execute('INSERT INTO applications(user_id,whatsapp,location,description) VALUES(?,?,?,?)',(uid,str(d.get('whatsapp',''))[:50],str(d.get('location',''))[:100],str(d.get('description',''))[:2000]))
                rate_hit('reg_ip',self.client_ip(),5,3600,3600)
                self.auth_event(uid,'register')
                return self.respond({'ok':True,'message':'Application received. An administrator will review it.' if role=='provider' else 'Account created. You can now sign in.'},201)
            if path=='/api/login':
                email=str(d.get('email','')).strip().lower(); pw=str(d.get('password',''))
                if not EMAIL_RE.fullmatch(email) or not pw or len(pw)>200:return self.respond({'error':'Email or password is incorrect'},401)
                wait=rate_check('login_ip',self.client_ip(),20,900) or rate_check('login_em',email,6,900)
                if wait:return self.respond({'error':f'Too many sign-in attempts. Try again in about {max(1,wait//60) or 1} minute(s).'},429)
                user=one('SELECT * FROM users WHERE email=?',(email,))
                ok=verify(pw,user['password']) if user else (verify(pw,_dummy_hash()) or False)
                if not user or not ok:
                    rate_hit('login_ip',self.client_ip(),20,900,900); rate_hit('login_em',email,6,900,900)
                    if user:self.auth_event(user['id'],'login_failed')
                    return self.respond({'error':'Email or password is incorrect'},401)
                if user['status'] in ('inactive','suspended','deleted'):
                    self.auth_event(user['id'],'login_blocked_status')
                    return self.respond({'error':'This account is inactive or suspended. Contact the VYBE administrator.'},403)
                rate_clear('login_em',email)
                if pw_needs_rehash(user['password']):
                    try:
                        with connect() as c:c.execute('UPDATE users SET password=? WHERE id=?',(pw_hash(pw),user['id']))
                    except sqlite3.Error:pass
                if user['role']=='admin' and user.get('totp_enabled'):
                    mtoken=secrets.token_urlsafe(32); exp=int(time.time())+600
                    with connect() as c:c.execute('INSERT INTO mfa_challenges(user_id,token_hash,expires_at) VALUES(?,?,?)',(user['id'],sha256_hex(mtoken),exp))
                    self.auth_event(user['id'],'mfa_challenge')
                    return self.respond({'ok':True,'mfa_required':True,'mfa_token':mtoken},200)
                cookie=self.create_session(user['id'],user['role'])
                self.auth_event(user['id'],'login_success')
                return self.respond({'ok':True},200,cookie)
            if path=='/api/login/mfa':
                mtoken=str(d.get('mfa_token','')); code=str(d.get('code',''))
                if not mtoken or len(mtoken)>200:return self.respond({'error':'MFA verification is required'},400)
                ch=one('SELECT * FROM mfa_challenges WHERE token_hash=?',(sha256_hex(mtoken),))
                if not ch or ch['used'] or ch['expires_at']<int(time.time()):return self.respond({'error':'This verification session expired. Sign in again.'},401)
                user=one('SELECT * FROM users WHERE id=?',(ch['user_id'],))
                if not user or user['status'] in ('inactive','suspended','deleted') or user['role']!='admin' or not user.get('totp_enabled'):
                    return self.respond({'error':'This verification session expired. Sign in again.'},401)
                wait=rate_check('mfa_ip',self.client_ip(),10,900) or rate_check('mfa_u',str(user['id']),6,900)
                if wait:return self.respond({'error':f'Too many verification attempts. Try again in about {max(1,wait//60) or 1} minute(s).'},429)
                if not totp_verify(user['totp_secret'],code):
                    rate_hit('mfa_ip',self.client_ip(),10,900,900); rate_hit('mfa_u',str(user['id']),6,900,900)
                    self.auth_event(user['id'],'mfa_failed')
                    return self.respond({'error':'Incorrect verification code. Check your authenticator app and try again.'},401)
                with connect() as c:c.execute('UPDATE mfa_challenges SET used=1 WHERE id=?',(ch['id'],))
                rate_clear('mfa_u',str(user['id']))
                cookie=self.create_session(user['id'],user['role'])
                self.auth_event(user['id'],'login_success_mfa')
                return self.respond({'ok':True},200,cookie)
            if path=='/api/logout':
                token=self.get_cookie()
                if token:
                    with connect() as c:c.execute('UPDATE sessions SET revoked=1 WHERE token_hash=?',(sha256_hex(token),))
                return self.respond({'ok':True},200,(COOKIE,'',0))
            if path=='/api/admin/vipmember':
                adm=self.admin()
                if not adm:return
                uid=int(d.get('user_id') or 0);action=str(d.get('action') or '')
                target=one("SELECT id,status FROM users WHERE id=? AND role='customer' AND status!='deleted'",(uid,))
                if not target:return self.respond({'error':'Customer account not found'},404)
                if action not in ('activate','renew','setexpiry','suspend','expire'):return self.respond({'error':'Choose activate, renew, setexpiry, suspend or expire'},400)
                mem=one('SELECT * FROM vip_memberships WHERE user_id=?',(uid,))
                if action in ('activate','renew'):
                    if target['status']!='active':return self.respond({'error':'Activate the customer account before granting VIP access'},400)
                    try:days=max(1,min(3650,int(d.get('days') or 0) or int(setting_json('vip_duration_days',30) or 30)))
                    except (TypeError,ValueError):days=30
                    exp=vip_expiry_default(days)
                    with connect() as c:
                        c.execute("INSERT INTO vip_memberships(user_id,status,started_at,expires_at,updated_at) VALUES(?,'active',CURRENT_TIMESTAMP,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET status='active',expires_at=excluded.expires_at,updated_at=CURRENT_TIMESTAMP",(uid,exp))
                        c.execute('UPDATE users SET is_vip=1 WHERE id=?',(uid,))
                        mid=c.execute('SELECT id FROM vip_memberships WHERE user_id=?',(uid,)).fetchone()['id']
                        c.execute('INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?,?,?,?)',(mid,adm['id'],'activated' if action=='activate' else 'renewed','active',exp))
                    audit(adm['id'],'vip_'+action,'user',uid,'expires '+exp)
                    return self.respond({'ok':True,'expires_at':exp})
                if action=='setexpiry':
                    if not mem or mem['status']!='active':return self.respond({'error':'Activate the membership before setting an expiry'},400)
                    try:days=max(1,min(3650,int(d.get('days') or 0)))
                    except (TypeError,ValueError):days=30
                    exp=vip_expiry_default(days)
                    with connect() as c:
                        c.execute('UPDATE vip_memberships SET expires_at=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?',(exp,uid))
                        c.execute('INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?,?,?,?)',(mem['id'],adm['id'],'expiry_set','active',exp))
                    audit(adm['id'],'vip_setexpiry','user',uid,'expires '+exp)
                    return self.respond({'ok':True,'expires_at':exp})
                newst='suspended' if action=='suspend' else 'expired'
                with connect() as c:
                    c.execute('UPDATE vip_memberships SET status=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?',(newst,uid))
                    c.execute('UPDATE users SET is_vip=0 WHERE id=?',(uid,))
                    c.execute('INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?,?,?,?)',(mem['id'] if mem else None,adm['id'],action,newst,mem['expires_at'] if mem else None))
                audit(adm['id'],'vip_'+action,'user',uid,'')
                return self.respond({'ok':True,'status':newst})
            if path=='/api/admin/admins':
                a=self.admin()
                if not a:return
                if not a.get('is_super'):return self.respond({'error':'Overall administrator access required'},403)
                name=str(d.get('name','')).strip();email=str(d.get('email','')).strip().lower();password=str(d.get('password',''))
                if not name or len(name)>100 or not EMAIL_RE.fullmatch(email):return self.respond({'error':'Enter a name and a valid email address'},400)
                issues=password_issues(password,'admin',email,name)
                if issues:return self.respond({'error':'Choose a stronger administrator password: use '+', '.join(issues)+'.'},400)
                with connect() as c:
                    cur=c.execute('INSERT INTO users(name,email,role,password,status,is_super) VALUES(?,?,?,?,?,?)',(name,email,'admin',pw_hash(password),'active',int(bool(d.get('is_super')))))
                    newid=cur.lastrowid
                audit(a['id'],'admin_created','user',newid,email)
                return self.respond({'ok':True,'id':newid},201)
            if re.fullmatch(r'/api/admin/admin/\d+',path):
                a=self.admin()
                if not a:return
                if not a.get('is_super'):return self.respond({'error':'Overall administrator access required'},403)
                tid=int(path.rsplit('/',1)[-1])
                target=one("SELECT * FROM users WHERE id=? AND role='admin' AND status!='deleted'",(tid,))
                if not target:return self.respond({'error':'Administrator account not found'},404)
                if target.get('is_owner') and tid!=a['id']:return self.respond({'error':'The protected owner account cannot be changed by another administrator'},403)
                action=str(d.get('action') or '')
                supers=one("SELECT COUNT(*) n FROM users WHERE role='admin' AND is_super=1 AND status='active'")['n']
                with connect() as c:
                    if action=='status':
                        status=d.get('status')
                        if status not in ('active','suspended','deleted'):return self.respond({'error':'Choose active, suspended, or deleted'},400)
                        if tid==a['id'] and status!='active':return self.respond({'error':'You cannot suspend or delete your own administrator account'},400)
                        if target['is_super'] and status!='active' and supers<=1:return self.respond({'error':'At least one active overall administrator must remain'},400)
                        c.execute('UPDATE users SET status=? WHERE id=?',(status,tid))
                    elif action=='details':
                        name=str(d.get('name','')).strip();email=str(d.get('email','')).strip().lower()
                        if not name or len(name)>100 or not EMAIL_RE.fullmatch(email):return self.respond({'error':'Enter a valid name and email'},400)
                        c.execute('UPDATE users SET name=?,email=? WHERE id=?',(name,email,tid))
                    elif action=='password':
                        password=str(d.get('password',''))
                        issues=password_issues(password,'admin',target['email'],target['name'])
                        if issues:return self.respond({'error':'Choose a stronger administrator password: use '+', '.join(issues)+'.'},400)
                        c.execute('UPDATE users SET password=? WHERE id=?',(pw_hash(password),tid))
                    elif action=='super':
                        make=bool(d.get('is_super'))
                        if not make:
                            if tid==a['id']:return self.respond({'error':'You cannot remove your own overall-admin access'},400)
                            if target['is_super'] and supers<=1:return self.respond({'error':'At least one active overall administrator must remain'},400)
                        c.execute('UPDATE users SET is_super=? WHERE id=?',(int(make),tid))
                    else:return self.respond({'error':'Unknown admin action'},404)
                audit(a['id'],'admin_'+action,'user',tid,json.dumps(d))
                return self.respond({'ok':True})
            if path.startswith('/api/admin/'):
                a=self.admin()
                if not a:return
                parts=path.split('/'); action=parts[3]; ident=int(parts[4]) if len(parts)>4 and parts[4].isdigit() else 0
                with connect() as c:
                    if action=='application':
                        status=d.get('status'); allowed={'pending_review','contact_required','approved','rejected','suspended'}
                        if status not in allowed:return self.respond({'error':'Invalid application status'},400)
                        c.execute('UPDATE applications SET status=?,notes=? WHERE id=?',(status,d.get('notes',''),ident));
                        if status=='approved':
                            c.execute("UPDATE users SET status='active' WHERE id=(SELECT user_id FROM applications WHERE id=?)",(ident,))
                            c.execute("UPDATE profiles SET status='approved',feedback='',updated_at=CURRENT_TIMESTAMP WHERE provider_id=(SELECT user_id FROM applications WHERE id=?)",(ident,))
                        if status in ('rejected','suspended'):c.execute('UPDATE users SET status=? WHERE id=(SELECT user_id FROM applications WHERE id=?)',(status,ident))
                    elif action=='profile':
                        status=d.get('status')
                        if status not in ('approved','rejected','changes_requested','unpublished','suspended'):return self.respond({'error':'Invalid profile decision'},400)
                        c.execute('UPDATE profiles SET status=?,feedback=?,verified=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(status,d.get('feedback',''),int(bool(d.get('verified',False))),ident))
                        if status=='approved':
                            c.execute("UPDATE users SET status='active' WHERE id=(SELECT provider_id FROM profiles WHERE id=?) AND status NOT IN ('suspended','deleted')",(ident,))
                    elif action=='user':
                        status=d.get('status','suspended')
                        if status not in ('active','inactive','suspended','deleted'):return self.respond({'error':'Choose active, inactive, suspended, or deleted'},400)
                        target=c.execute("SELECT role FROM users WHERE id=? AND role!='admin'",(ident,)).fetchone()
                        if not target:return self.respond({'error':'Customer or provider account not found'},404)
                        c.execute('UPDATE users SET status=? WHERE id=?',(status,ident))
                        if status=='deleted' and target['role']=='provider':c.execute("UPDATE profiles SET status='unpublished',is_vip=0,updated_at=CURRENT_TIMESTAMP WHERE provider_id=?",(ident,))
                    elif action=='report':c.execute('UPDATE reports SET status=? WHERE id=?',(d.get('status','resolved'),ident))
                    elif action=='settings':
                        if d.get('key') not in ('platform_name','contact_email','vip_price_ugx','vip_duration_days'):return self.respond({'error':'Unknown setting'},400)
                        c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(d.get('key'),str(d.get('value',''))[:200]))
                    elif action=='catalog':
                        services=d.get('services');locations=d.get('locations');
                        if 'services' in d and not valid_catalog(services,'services'):return self.respond({'error':'Services must be unique, non-empty names up to 160 characters.'},400)
                        if 'locations' in d and not valid_catalog(locations,'locations'):return self.respond({'error':'Locations must be unique; each name can be up to 160 characters.'},400)
                        if 'services' in d:c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('service_catalog',json.dumps([str(x).strip() for x in services])))
                        if 'locations' in d:c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',('locations',json.dumps([str(x).strip() for x in locations])))
                    elif action=='review':
                        status=d.get('status')
                        if status not in ('approved','rejected'):return self.respond({'error':'Review status must be approved or rejected'},400)
                        c.execute('UPDATE reviews SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(status,ident))
                    elif action=='provider':
                        enable=bool(d.get('is_vip'));prov=c.execute("SELECT p.id FROM profiles p WHERE p.provider_id=? AND p.status='approved'",(ident,)).fetchone()
                        account=c.execute("SELECT 1 FROM users WHERE id=? AND role='provider' AND status='active'",(ident,)).fetchone()
                        if enable and (not prov or not account):return self.respond({'error':'Only active providers with an approved profile can be featured in VIP'},400)
                        c.execute('UPDATE profiles SET is_vip=? WHERE provider_id=?',(int(enable),ident))
                    elif action=='customer':
                        enable=bool(d.get('is_vip'));target=c.execute("SELECT status FROM users WHERE id=? AND role='customer' AND status!='deleted'",(ident,)).fetchone()
                        if not target:return self.respond({'error':'Customer account not found'},404)
                        if enable and target['status']!='active':return self.respond({'error':'Activate the customer account before granting VIP access'},400)
                        c.execute("UPDATE users SET is_vip=? WHERE id=? AND role='customer'",(int(enable),ident))
                        exp=vip_expiry_default()
                        if enable:
                            c.execute("INSERT INTO vip_memberships(user_id,status,started_at,expires_at,updated_at) VALUES(?,'active',CURRENT_TIMESTAMP,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET status='active',expires_at=excluded.expires_at,updated_at=CURRENT_TIMESTAMP",(ident,exp))
                            mid=c.execute('SELECT id FROM vip_memberships WHERE user_id=?',(ident,)).fetchone()['id']
                            c.execute("INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?, 'activated','active',?)",(mid,a['id'],exp))
                        else:
                            c.execute("UPDATE vip_memberships SET status='expired',updated_at=CURRENT_TIMESTAMP WHERE user_id=?",(ident,))
                            midx=c.execute('SELECT id FROM vip_memberships WHERE user_id=?',(ident,)).fetchone()
                            if midx:c.execute("INSERT INTO vip_membership_history(membership_id,admin_id,action,status,expires_at) VALUES(?,?, 'deactivated','expired',NULL)",(midx['id'],a['id']))
                    else:return self.respond({'error':'Unknown action'},404)
                audit(a['id'],action,parts[3],ident,json.dumps(d)); return self.respond({'ok':True})
            if path not in ('/api/password/forgot','/api/password/reset') and not u:return self.respond({'error':'Sign in required'},401)
            if path=='/api/messages':
                if u['role'] not in ('customer','provider') or u['status']!='active':return self.respond({'error':'An active customer or provider account is required'},403)
                pid=int(d.get('profile_id') or 0);body=str(d.get('body','')).strip()
                if not body or len(body)>2000:return self.respond({'error':'Write a message of 1 to 2,000 characters'},400)
                prof=one('SELECT * FROM profiles WHERE id=?',(pid,))
                if not prof:return self.respond({'error':'Profile not found'},404)
                if u['role']=='customer':
                    if prof['status']!='approved' or not one("SELECT 1 FROM users WHERE id=? AND status='active'",(prof['provider_id'],)):return self.respond({'error':'This profile is not available for messages'},404)
                    if prof['is_vip'] and not vip_client(u['id']):return self.respond({'error':'VIP membership is required to message this provider','code':'vip_required'},403)
                    customer_id=u['id'];recipient=prof['provider_id']
                elif u['role']=='provider':
                    if prof['provider_id']!=u['id']:return self.respond({'error':'You can reply only to conversations started by a customer on your own profile'},403)
                    customer_id=int(d.get('customer_id') or 0)
                    if not one("SELECT 1 FROM messages WHERE profile_id=? AND customer_id=?",(pid,customer_id)) or not one("SELECT 1 FROM users WHERE id=? AND role='customer' AND status='active'",(customer_id,)):return self.respond({'error':'Customer conversation not found'},404)
                    if prof['is_vip'] and not vip_client(customer_id):return self.respond({'error':'VIP providers can only reply to active VIP members'},403)
                    recipient=customer_id
                with connect() as c:c.execute('INSERT INTO messages(profile_id,customer_id,sender_id,body) VALUES(?,?,?,?)',(pid,customer_id,u['id'],body))
                return self.respond({'ok':True},201)
            if path=='/api/saved':
                if u['role']!='customer' or u['status']!='active':return self.respond({'error':'An active customer account is required'},403)
                prof=one("SELECT p.id,p.is_vip FROM profiles p JOIN users owner ON owner.id=p.provider_id WHERE p.id=? AND p.status='approved' AND owner.status='active'",(int(d.get('profile_id') or 0),))
                if not prof:return self.respond({'error':'Profile not found'},404)
                if prof['is_vip'] and not vip_client(u['id']):return self.respond({'error':'VIP membership is required to save this profile','code':'vip_required'},403)
                existing=one('SELECT id FROM saved_profiles WHERE user_id=? AND profile_id=?',(u['id'],prof['id']))
                with connect() as c:
                    if existing:c.execute('DELETE FROM saved_profiles WHERE id=?',(existing['id'],));saved=False
                    else:c.execute('INSERT INTO saved_profiles(user_id,profile_id) VALUES(?,?)',(u['id'],prof['id']));saved=True
                return self.respond({'ok':True,'saved':saved})
            if path=='/api/vip/request':
                if u['role']!='customer' or u['status']!='active':return self.respond({'error':'An active customer account is required'},403)
                st=vip_state(u['id'])
                if st['status']=='active':return self.respond({'error':'Your VIP membership is already active'},400)
                if st['status']=='pending':return self.respond({'error':'Your VIP request is already awaiting administrator approval'},400)
                with connect() as c:
                    c.execute("INSERT INTO vip_memberships(user_id,status,updated_at) VALUES(?,'pending',CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET status='pending',updated_at=CURRENT_TIMESTAMP",(u['id'],))
                    mid=c.execute('SELECT id FROM vip_memberships WHERE user_id=?',(u['id'],)).fetchone()['id']
                    c.execute('INSERT INTO vip_membership_history(membership_id,admin_id,action,status) VALUES(?,?,?,?)',(mid,None,'requested','pending'))
                return self.respond({'ok':True,'status':'pending'},201)
            if path=='/api/reviews':
                if u['role']!='customer' or u['status']!='active':return self.respond({'error':'An active customer account is required'},403)
                pid=int(d.get('profile_id') or 0);rating=int(d.get('rating') or 0);body=str(d.get('body','')).strip()
                prof=one("SELECT p.id,p.is_vip FROM profiles p JOIN users u ON u.id=p.provider_id WHERE p.id=? AND p.status='approved' AND u.status='active'",(pid,))
                if not prof:return self.respond({'error':'This profile is not available to your account'},404)
                if prof['is_vip'] and not vip_client(u['id']):return self.respond({'error':'VIP membership is required to review this provider','code':'vip_required'},403)
                if rating<1 or rating>5 or len(body)>1000:return self.respond({'error':'Use a 1–5 star rating and a review under 1,000 characters'},400)
                with connect() as c:c.execute("INSERT INTO reviews(profile_id,customer_id,rating,body,status) VALUES(?,?,?,?, 'pending') ON CONFLICT(profile_id,customer_id) DO UPDATE SET rating=excluded.rating,body=excluded.body,status='pending',updated_at=CURRENT_TIMESTAMP",(pid,u['id'],rating,body))
                return self.respond({'ok':True,'status':'pending'},201)
            if path=='/api/provider/profile':
                if u['role']!='provider':return self.respond({'error':'Provider login required'},403)
                if u['status'] in ('suspended','deleted','rejected','expired'):return self.respond({'error':'This provider account cannot edit a profile. Contact the administrator.'},403)
                display=d.get('display_name','').strip(); bio=d.get('bio','').strip(); location=d.get('location','').strip(); categories=d.get('categories',[]); photos=d.get('photos',[]);videos=d.get('videos',[]);services=d.get('services',[]);service_mode=d.get('service_mode','both')
                if not display or len(display)>80 or not bio or len(bio)>1200 or not location or location not in setting_json('locations',[]):return self.respond({'error':'Enter a valid profile name, biography, and approved location'},400)
                if service_mode not in ('in_call','delivery','both'):return self.respond({'error':'Choose in-call, delivery, or both'},400)
                if not isinstance(categories,list) or not categories or len(categories)>8 or any(not isinstance(x,str) or not x.strip() or len(x)>40 for x in categories):return self.respond({'error':'Choose 1 to 8 valid profile categories'},400)
                catalog=setting_json('service_catalog',[])
                if not isinstance(services,list) or not services or len(services)>20:return self.respond({'error':'Choose at least one service from the admin-managed catalogue'},400)
                normalized=[]
                for service in services:
                    if not isinstance(service,dict) or service.get('name') not in catalog:return self.respond({'error':'Choose services from the admin-managed catalogue'},400)
                    try:price=float(service.get('price',service.get('price_min',0)))
                    except (TypeError,ValueError):return self.respond({'error':'Service prices must be valid amounts'},400)
                    if price<0 or price>100000000:return self.respond({'error':'Enter a valid service price in UGX'},400)
                    normalized.append({'name':service['name'],'price':int(price)})
                if len({v['name'] for v in normalized})!=len(normalized):return self.respond({'error':'Choose each service only once'},400)
                if not isinstance(photos,list) or len(photos)>10:return self.respond({'error':'Upload up to 10 profile photos'},400)
                if not photos or any(not isinstance(x,str) or not x for x in photos):return self.respond({'error':'Add at least one valid profile photo'},400)
                if not isinstance(videos,list) or len(videos)>2 or any(not isinstance(x,str) or not x for x in videos):return self.respond({'error':'Upload up to 2 valid profile videos'},400)
                if (any(str(x).startswith('data:') for x in photos) or any(str(x).startswith('data:') for x in videos)) and not d.get('image_consent'):return self.respond({'error':'Confirm that you own or have consent to use every uploaded image and video'},400)
                try: photos=[save_image(str(x)) for x in photos]
                except (ValueError,base64.binascii.Error) as e:return self.respond({'error':str(e)},400)
                try: videos=[save_video(str(x)) if str(x).startswith('data:') else str(x) for x in videos]
                except (ValueError,base64.binascii.Error) as e:return self.respond({'error':str(e)},400)
                if any(not re.fullmatch(r'/media/[0-9a-f]{32}\.(?:mp4|webm|mov)',v) or not (ROOT/v.lstrip('/')).is_file() for v in videos):return self.respond({'error':'Invalid profile video'},400)
                with connect() as c:
                    c.execute('UPDATE users SET name=? WHERE id=?',(display,u['id']))
                    c.execute('UPDATE applications SET location=?,description=? WHERE user_id=?',(location,bio,u['id']))
                    c.execute("INSERT INTO profiles(provider_id,display_name,bio,location,categories,photos,videos,services,service_mode,contact_phone,contact_whatsapp,show_phone,show_whatsapp,status,feedback) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending','') ON CONFLICT(provider_id) DO UPDATE SET display_name=excluded.display_name,bio=excluded.bio,location=excluded.location,categories=excluded.categories,photos=excluded.photos,videos=excluded.videos,services=excluded.services,service_mode=excluded.service_mode,contact_phone=excluded.contact_phone,contact_whatsapp=excluded.contact_whatsapp,show_phone=excluded.show_phone,show_whatsapp=excluded.show_whatsapp,status='pending',feedback='',updated_at=CURRENT_TIMESTAMP",(u['id'],display,bio,location,json.dumps(categories),json.dumps(photos),json.dumps(videos),json.dumps(normalized),service_mode,d.get('contact_phone','')[:50],d.get('contact_whatsapp','')[:50],int(bool(d.get('show_phone'))),int(bool(d.get('show_whatsapp')))))
                return self.respond({'ok':True,'status':'pending'})
            if path=='/api/report':
                if u['role']!='customer' or u['status']!='active':return self.respond({'error':'An active customer account is required'},403)
                prof=one("SELECT p.id,p.is_vip FROM profiles p JOIN users u ON u.id=p.provider_id WHERE p.id=? AND p.status='approved' AND u.status='active'",(d.get('profile_id'),))
                if not prof:return self.respond({'error':'Profile not found'},404)
                if prof['is_vip'] and not vip_client(u['id']):return self.respond({'error':'VIP membership is required to report this profile','code':'vip_required'},403)
                with connect() as c:c.execute('INSERT INTO reports(reporter_id,profile_id,reason) VALUES(?,?,?)',(u['id'],prof['id'],d.get('reason','')))
                return self.respond({'ok':True},201)
            if path=='/api/password/forgot':
                email=str(d.get('email','')).strip().lower()
                generic={'ok':True,'message':'If an account with that email exists, you will receive password-reset instructions.'}
                wait=rate_check('forgot_ip',self.client_ip(),8,3600) or rate_check('forgot_em',email if EMAIL_RE.fullmatch(email) else 'invalid',3,3600)
                if wait:return self.respond({'error':'Too many reset requests. Try again later.'},429)
                rate_hit('forgot_ip',self.client_ip(),8,3600,3600)
                if EMAIL_RE.fullmatch(email):
                    rate_hit('forgot_em',email,3,3600,3600)
                    user=one("SELECT id,email,name,role FROM users WHERE email=? AND status NOT IN ('deleted','suspended','inactive')",(email,))
                    if user:
                        token=secrets.token_urlsafe(32); exp=int(time.time())+1800
                        with connect() as c:
                            c.execute('UPDATE password_resets SET used=1 WHERE user_id=? AND used=0',(user['id'],))
                            c.execute('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(?,?,?)',(user['id'],sha256_hex(token),exp))
                        self.auth_event(user['id'],'reset_requested')
                        link=f'{APP_ORIGIN}/reset?token={token}'
                        sent=self._send_email(user['email'],'Reset your VYBE password',f"Hello {user['name']},\n\nSomeone requested a password reset for your VYBE account. This link expires in 30 minutes and can be used once:\n\n{link}\n\nIf you did not request this, you can ignore this email. Your password has not changed.\n\n— VYBE")
                        if not sent and DEV_RESET_LINK:
                            return self.respond({**generic,'dev_reset_link':link})
                return self.respond(generic)
            if path=='/api/password/reset':
                token=str(d.get('token','')); password=str(d.get('password',''))
                wait=rate_check('reset_ip',self.client_ip(),15,3600)
                if wait:return self.respond({'error':'Too many reset attempts. Try again later.'},429)
                rate_hit('reset_ip',self.client_ip(),15,3600,3600)
                invalid={'error':'This reset link is invalid or has expired. Request a new one.'}
                if not token or len(token)>200:return self.respond(invalid,400)
                rec=one('SELECT * FROM password_resets WHERE token_hash=?',(sha256_hex(token),))
                if not rec or rec['used'] or rec['expires_at']<int(time.time()):return self.respond(invalid,400)
                user=one("SELECT * FROM users WHERE id=? AND status NOT IN ('deleted')",(rec['user_id'],))
                if not user:return self.respond(invalid,400)
                issues=password_issues(password,user['role'],user['email'],user['name'])
                if issues:return self.respond({'error':'Choose a stronger password: use '+', '.join(issues)+'.'},400)
                if verify(password,user['password']):return self.respond({'error':'Choose a password you have not used before.'},400)
                with connect() as c:
                    c.execute('UPDATE password_resets SET used=1 WHERE id=?',(rec['id'],))
                    c.execute('UPDATE users SET password=? WHERE id=?',(pw_hash(password),user['id']))
                    c.execute('UPDATE sessions SET revoked=1 WHERE user_id=?',(user['id'],))
                self.auth_event(user['id'],'reset_completed')
                return self.respond({'ok':True,'message':'Your password has been updated. Sign in with your new password.'})
            if path=='/api/account/password':
                if not u:return self.respond({'error':'Sign in required'},401)
                if len(d.get('password',''))>200 or not verify(d.get('currentPassword',''),one('SELECT password FROM users WHERE id=?',(u['id'],))['password']):return self.respond({'error':'Current password is incorrect or the new password is too short'},400)
                me=one('SELECT name,email,role FROM users WHERE id=?',(u['id'],))
                issues=password_issues(d.get('password',''),me['role'],me['email'],me['name'])
                if issues:return self.respond({'error':'Choose a stronger password: use '+', '.join(issues)+'.'},400)
                if verify(d.get('password',''),one('SELECT password FROM users WHERE id=?',(u['id'],))['password']):return self.respond({'error':'Choose a password you have not used before.'},400)
                with connect() as c:c.execute('UPDATE users SET password=? WHERE id=?',(pw_hash(d['password']),u['id']))
                self.revoke_sessions(u['id'],keep_current=True)
                self.auth_event(u['id'],'password_changed')
                return self.respond({'ok':True,'message':'Password updated. Other devices have been signed out.'})
            if path=='/api/account/mfa/setup':
                if not u:return self.respond({'error':'Sign in required'},401)
                if u['role']!='admin':return self.respond({'error':'Two-factor authentication is available for administrator accounts'},403)
                if not verify(str(d.get('password','')),one('SELECT password FROM users WHERE id=?',(u['id'],))['password']):return self.respond({'error':'Password is incorrect'},401)
                secret=totp_secret_new()
                with connect() as c:c.execute('UPDATE users SET totp_secret=?,totp_enabled=0 WHERE id=?',(secret,u['id']))
                self.auth_event(u['id'],'mfa_setup_started')
                return self.respond({'ok':True,'secret':secret,'otpauth':f'otpauth://totp/VYBE:{u["email"]}?secret={secret}&issuer=VYBE&digits=6&period=30'})
            if path=='/api/account/mfa/enable':
                if not u:return self.respond({'error':'Sign in required'},401)
                user=one('SELECT * FROM users WHERE id=?',(u['id'],))
                if user['role']!='admin' or not user.get('totp_secret') or user.get('totp_enabled'):return self.respond({'error':'Start two-factor setup first'},400)
                if not totp_verify(user['totp_secret'],str(d.get('code',''))):return self.respond({'error':'Incorrect verification code. Check your authenticator app and try again.'},401)
                with connect() as c:c.execute('UPDATE users SET totp_enabled=1 WHERE id=?',(u['id'],))
                self.auth_event(u['id'],'mfa_enabled')
                return self.respond({'ok':True,'message':'Two-factor authentication is now active for your administrator account.'})
            if path=='/api/account/mfa/disable':
                if not u:return self.respond({'error':'Sign in required'},401)
                user=one('SELECT * FROM users WHERE id=?',(u['id'],))
                if user['role']!='admin' or not user.get('totp_enabled'):return self.respond({'error':'Two-factor authentication is not active'},400)
                wait=rate_check('mfa_dis',str(u['id']),5,3600)
                if wait:return self.respond({'error':'Too many attempts. Try again later.'},429)
                pw_ok=verify(str(d.get('password','')),user['password'])
                code_ok=totp_verify(user['totp_secret'],str(d.get('code','')))
                if not pw_ok or not code_ok:
                    rate_hit('mfa_dis',str(u['id']),5,3600,3600); self.auth_event(u['id'],'mfa_disable_failed')
                    return self.respond({'error':'Password or verification code is incorrect'},401)
                rate_clear('mfa_dis',str(u['id']))
                with connect() as c:
                    c.execute("UPDATE users SET totp_secret='',totp_enabled=0 WHERE id=?",(u['id'],))
                    c.execute('UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash!=?',(u['id'],sha256_hex(self.get_cookie()) if self.get_cookie() else '__none__'))
                    c.execute('DELETE FROM mfa_challenges WHERE user_id=?',(u['id'],))
                self.auth_event(u['id'],'mfa_disabled')
                return self.respond({'ok':True,'message':'Two-factor authentication has been turned off.'})
            if path=='/api/account/logout-all':
                if not u:return self.respond({'error':'Sign in required'},401)
                self.revoke_sessions(u['id'])
                self.auth_event(u['id'],'logout_all')
                return self.respond({'ok':True,'message':'Signed out on all devices.'},200,(COOKIE,'',0))
            if path=='/api/account/profile':
                if not u:return self.respond({'error':'Sign in required'},401)
                if not d.get('name','').strip():return self.respond({'error':'Name is required'},400)
                with connect() as c:c.execute('UPDATE users SET name=?,phone=? WHERE id=?',(d['name'].strip()[:100],d.get('phone','')[:50],u['id']))
                return self.respond({'ok':True})
        except sqlite3.IntegrityError as e: return self.respond({'error':'That email is already registered or the submitted data is invalid'},400)
        except Exception as e: return self.respond({'error':'The request could not be completed'},500)
        return self.respond({'error':'Not found'},404)

def cli_reset_admin_password():
    """Interactive CLI recovery for an administrator password. Requires local shell access; no backdoor."""
    init()
    admins=rows("SELECT id,name,email FROM users WHERE role='admin' AND status='active' ORDER BY is_super DESC,created_at ASC")
    if not admins:print('No active administrator account exists. Create one with VYBE_ADMIN_EMAIL / VYBE_ADMIN_PASSWORD and rerun seed.py.'); return 1
    print('Active administrator accounts:')
    for i,a in enumerate(admins,1):print(f'  {i}. {a["email"]} ({a["name"]})')
    choice=input('Choose account number: ').strip()
    try:target=admins[int(choice)-1]
    except (ValueError,IndexError):print('Invalid choice.'); return 1
    pw=getpass.getpass('New password: '); pw2=getpass.getpass('Confirm password: ')
    if pw!=pw2:print('Passwords do not match.'); return 1
    issues=password_issues(pw,'admin',target['email'],target['name'])
    if issues:print('Password too weak: use '+', '.join(issues)+'.'); return 1
    with connect() as c:
        c.execute('UPDATE users SET password=? WHERE id=?',(pw_hash(pw),target['id']))
        c.execute('UPDATE sessions SET revoked=1 WHERE user_id=?',(target['id'],))
        c.execute('INSERT INTO auth_events(user_id,event,ip) VALUES(?,?,?)',(target['id'],'admin_password_cli_reset','local'))
    print('Password updated. All sessions for this administrator have been signed out.'); return 0

if __name__=='__main__':
    if '--reset-admin-password' in sys.argv:raise SystemExit(cli_reset_admin_password())
    port=int(os.environ.get('PORT',os.environ.get('VYBE_PORT','8004')));production=os.environ.get('VYBE_ENV','').strip().lower()=='production';host=os.environ.get('VYBE_HOST') or ('0.0.0.0' if production else '127.0.0.1');init(); print(f'VYBE — FIND YOUR VIBE available at http://{host}:{port}'); ThreadingHTTPServer((host,port),App).serve_forever()

