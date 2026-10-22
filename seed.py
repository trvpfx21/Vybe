"""Repeatable development-only demo data loader."""
import os, secrets, string
if os.environ.get('VYBE_ENV','').strip().lower()=='production':
    raise RuntimeError('seed.py is for local development only and cannot run in production')
import server
server.init()

def ensure(c,name,email,role,status='active',phone='',password=None):
    found=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
    if found:return found['id']
    cur=c.execute('INSERT INTO users(name,email,phone,role,password,status) VALUES(?,?,?,?,?,?)',(name,email,phone,role,server.pw_hash(password or 'EmpireDemo!2026'),status)); return cur.lastrowid

def ensure_admin(c):
    """Create the administrator from env vars or a one-time random password. Never a hardcoded credential."""
    email=(os.environ.get('VYBE_ADMIN_EMAIL') or 'admin@nightlife.test').strip().lower()
    found=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
    if found:
        c.execute("UPDATE users SET role='admin' WHERE id=? AND role!='admin'",(found['id'],))
        return found['id'],None
    pw=os.environ.get('VYBE_ADMIN_PASSWORD','').strip()
    generated=False
    if not pw:
        alphabet=string.ascii_letters+string.digits+'!@#$%&*'
        pw=''.join(secrets.choice(alphabet) for _ in range(16)); generated=True
    cur=c.execute('INSERT INTO users(name,email,role,password,status,is_super) VALUES(?,?,?,?,?,1)',('Administrator',email,'admin',server.pw_hash(pw),'active'))
    return cur.lastrowid,(email,pw) if generated else None

with server.connect() as c:
    admin,bootstrap=ensure_admin(c)
    customers=[ensure(c,n,f'customer{i}@nightlife.test','customer') for i,n in enumerate(['Amara N.','Jonah K.','Grace M.','Peter O.','Lydia S.'],1)]
    names=['Nia Rose','Ava Moon','Zuri Lane','Maya Bloom','Tara Sky','Lina Vale','Kira Sol','Rina Blue']
    providers=[]
    for i,n in enumerate(names,1):
        uid=ensure(c,n,f'provider{i}@nightlife.test','provider','suspended' if i==8 else 'active')
        c.execute('UPDATE users SET status=? WHERE id=?',('suspended' if i==8 else 'active',uid))
        providers.append(uid)
        c.execute('INSERT OR IGNORE INTO applications(user_id,whatsapp,location,description,status) VALUES(?,?,?,?,?)',(uid,f'+2567000000{i:02d}',('Kampala','Entebbe','Jinja')[i%3],f'{n} shares local culture, events and community updates.','suspended' if i==8 else 'approved'))
        c.execute('UPDATE applications SET status=? WHERE user_id=?',('suspended' if i==8 else 'approved',uid))
        if i<=7 and not c.execute('SELECT 1 FROM profiles WHERE provider_id=?',(uid,)).fetchone():
            avatars=['photo-1534528741775-53994a69daeb','photo-1500648767791-00dcc994a43e','photo-1531123897727-8f129e1688ce','photo-1506794778202-cad84cf45f1d','photo-1524504388940-b1c1722653e1','photo-1507003211169-0a1dd7228f2d','photo-1534528741775-53994a69daeb']
            bios=['Creative soul who loves live music, good conversation and finding new corners of Kampala.','A curious mind, weekend hiker and fan of thoughtful art and local food.','Here for genuine connections, dance nights and stories worth sharing.','Book lover and culture enthusiast. Always happy to swap recommendations.','Warm-hearted explorer who enjoys live shows, nature walks and meeting new people.','Music, photography and spontaneous trips around the Pearl of Africa.','A friendly face with a love for art walks, local cafes and good company.']
            cats=[['Music','Arts','Social'],['Outdoors','Food','Culture'],['Music','Dance','Social'],['Arts','Books','Culture'],['Outdoors','Music','Travel'],['Music','Photography','Travel'],['Art','Community','Travel']]
            state='approved' if i<=6 else 'pending'
            gallery=[f'https://images.unsplash.com/{avatars[(i-1+j)%len(avatars)]}?w=900&auto=format&fit=crop&q=85' for j in range(3)]
            c.execute("INSERT INTO profiles(provider_id,display_name,bio,location,categories,photos,status,verified) VALUES(?,?,?,?,?,?,?,?)",(uid,n,bios[i-1],('Kampala','Entebbe','Jinja')[i%3],__import__('json').dumps(cats[i-1]),__import__('json').dumps(gallery),state,1 if i in (1,3) else 0))
    for j in range(2):
        email=f'pending{j+1}@nightlife.test'
        if not c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone():
            uid=ensure(c,['Noah Demo','Ivy Demo'][j],email,'provider','pending')
            c.execute('INSERT INTO applications(user_id,whatsapp,location,description,status) VALUES(?,?,?,?,?)',(uid,'+256700001234','Kampala','A fictional application for platform demonstration.','pending_review'))
    if not c.execute('SELECT 1 FROM reports WHERE profile_id IS NOT NULL LIMIT 1').fetchone():c.execute("INSERT INTO reports(reporter_id,profile_id,reason) SELECT ?,id,'Demo report for profile review' FROM profiles WHERE status='approved' LIMIT 1",(customers[0],))
    c.execute("UPDATE settings SET value='VYBE' WHERE key='platform_name'")
print('VYBE demo data ready.')
print('Demo customer/provider password: EmpireDemo!2026 (fictional local-only accounts).')
if bootstrap:
    print(f'\n*** New administrator created: {bootstrap[0]}')
    print(f'*** One-time generated password (shown once, not stored): {bootstrap[1]}')
    print('*** Change it after first sign-in, or set VYBE_ADMIN_EMAIL / VYBE_ADMIN_PASSWORD before seeding.')
