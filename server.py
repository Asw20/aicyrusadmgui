"""Cyrus Console: dependency-free, tenant-isolated IMAP administration."""
import base64
import hashlib
import hmac
import imaplib
import json
import os
import re
import secrets
import sqlite3
import ssl
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('CYRUS_DATA_DIR', ROOT / '.data'))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'console.db'
SESSIONS = {}
AUTH_ATTEMPTS = {}
RIGHTS = 'lrswipkxtecdan'


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def initialize():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, email TEXT UNIQUE, name TEXT, salt TEXT, password TEXT);
        CREATE TABLE IF NOT EXISTS mailboxes(tenant TEXT, name TEXT, quota INTEGER, used INTEGER DEFAULT 0, PRIMARY KEY(tenant,name));
        CREATE TABLE IF NOT EXISTS acls(tenant TEXT, mailbox TEXT, principal TEXT, rights TEXT, PRIMARY KEY(tenant,mailbox,principal));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, tenant TEXT, action TEXT, target TEXT, created INTEGER);
        ''')


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def seed(c, tenant):
    for name, quota, used in [('user.alex', 2048, 642), ('user.jordan', 2048, 318), ('user.morgan', 4096, 1720), ('user.taylor', 2048, 97), ('shared.support', 5120, 2184), ('shared.engineering', 10240, 3240), ('shared.announcements', 1024, 124), ('user.alex.Archive', 1024, 286)]:
        c.execute('INSERT INTO mailboxes VALUES(?,?,?,?)', (tenant, name, quota, used))
        owner = name.split('.')[1] if name.startswith('user.') else 'admins'
        c.execute('INSERT INTO acls VALUES(?,?,?,?)', (tenant, name, owner, RIGHTS))
    c.execute('INSERT INTO acls VALUES(?,?,?,?)', (tenant, 'shared.support', 'support-team', 'lrswip'))


def quoted(value):
    if not isinstance(value, str) or not value or any(ord(x) < 32 or ord(x) > 126 for x in value):
        raise ValueError('Use a nonempty ASCII name without control characters.')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def tokens(raw):
    """Parse IMAP quoted strings, NIL and atoms for LIST/ACL responses."""
    text = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
    return [re.sub(r'\\(.)', r'\1', a) if not b else b for a, b in re.findall(r'"((?:[^"\\]|\\.)*)"|([^\s]+)', text)]


class Cyrus:
    def __init__(self, config):
        self.client = imaplib.IMAP4_SSL(config['host'], config['port'], ssl_context=ssl.create_default_context(), timeout=12)
        try:
            self.check(self.client.login(config['username'], config['password']))
            caps = {x.upper() for x in self.client.capabilities}
            if b'ACL' not in caps:
                raise ValueError('This server does not advertise the IMAP ACL capability.')
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            self.client.logout()
        except Exception:
            pass

    @staticmethod
    def check(result):
        status, data = result
        if status != 'OK':
            raise ValueError('Cyrus rejected the operation: ' + ' '.join(x.decode('utf-8', 'replace') for x in data if isinstance(x, bytes)))
        return data

    def list(self):
        output = []
        for row in self.check(self.client.list('""', '"*"')):
            if not isinstance(row, bytes):
                continue
            match = re.match(rb'\((.*?)\)\s+("(?:[^"\\]|\\.)*"|NIL)\s+(.+)$', row)
            if not match:
                continue
            delimiter = tokens(match[2])[0]
            name = tokens(match[3])[0]
            if b'\\Noselect' in match[1]:
                continue
            output.append({'name': name, 'delimiter': None if delimiter == 'NIL' else delimiter, 'quota': None, 'used': None})
        return output

    def acl(self, name):
        rows = self.check(self.client.getacl(quoted(name)))
        values = tokens(rows[0]) if rows and rows[0] else []
        return [{'principal': values[i], 'rights': values[i + 1]} for i in range(1, len(values) - 1, 2)]

    def quota(self, name):
        typ, rows = self.client.getquotaroot(quoted(name))
        if typ != 'OK':
            raise ValueError('Quota information is not available for this mailbox.')
        for group in rows:
            for row in group if isinstance(group, list) else []:
                if isinstance(row, bytes):
                    match = re.search(rb'STORAGE\s+(\d+)\s+(\d+)', row)
                    if match:
                        return {'used': round(int(match[1]) / 1024, 2), 'quota': round(int(match[2]) / 1024, 2)}
        return {'used': None, 'quota': None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Never log request bodies, credentials, or query strings.
        print('%s %s' % (self.command, self.path.split('?')[0]), flush=True)

    def send_json(self, data, status=200, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
        except cookies.CookieError:
            return None
        token = jar.get('session')
        session = SESSIONS.get(token.value) if token else None
        if session and session['expires'] > time.time():
            return session
        if token:
            SESSIONS.pop(token.value, None)
        return None

    def do_GET(self):
        if self.path.startswith('/api/'):
            return self.api()
        paths = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        item = paths.get(self.path.split('?')[0])
        if not item:
            return self.send_error(404)
        body = (ROOT / 'static' / item[0]).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', item[1] + '; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.api()

    def api(self):
        client = None
        try:
            for token, existing in list(SESSIONS.items()):
                if existing['expires'] <= time.time():
                    SESSIONS.pop(token, None)
            data = {}
            session = self.session()
            if self.command == 'POST':
                origin = self.headers.get('Origin')
                if origin and origin not in ('http://' + self.headers.get('Host', ''), 'https://' + self.headers.get('Host', '')):
                    return self.send_json({'error': 'Cross-origin request denied.'}, 403)
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self.send_json({'error': 'JSON required.'}, 415)
                length = int(self.headers.get('Content-Length', '0'))
                if length > 16384:
                    return self.send_json({'error': 'Request too large.'}, 413)
                data = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(data, dict):
                    raise ValueError('Expected a JSON object.')
            path = self.path.split('?')[0]
            if path in ('/api/register', '/api/login') and self.command == 'POST':
                now = time.time()
                for address, attempts in list(AUTH_ATTEMPTS.items()):
                    recent = [t for t in attempts if now - t < 300]
                    if recent:
                        AUTH_ATTEMPTS[address] = recent
                    else:
                        AUTH_ATTEMPTS.pop(address, None)
                address = self.client_address[0]
                attempts = AUTH_ATTEMPTS.setdefault(address, [])
                if len(attempts) >= 20:
                    return self.send_json({'error': 'Too many sign-in attempts. Try again in five minutes.'}, 429)
                attempts.append(now)
                email = str(data.get('email', '')).strip().lower()
                password = str(data.get('password', ''))
                if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(password) < 10 or len(password) > 256:
                    raise ValueError('Enter a valid email and a password of 10–256 characters.')
                with db() as c:
                    if path == '/api/register':
                        name = str(data.get('name', '')).strip()[:80]
                        if not name:
                            raise ValueError('Workspace name is required.')
                        tenant, salt = secrets.token_hex(16), secrets.token_hex(16)
                        try:
                            c.execute('INSERT INTO accounts VALUES(?,?,?,?,?)', (tenant, email, name, salt, password_hash(password, salt)))
                            seed(c, tenant)
                        except sqlite3.IntegrityError:
                            raise ValueError('An account with that email already exists.')
                    row = c.execute('SELECT * FROM accounts WHERE email=?', (email,)).fetchone()
                    if not row or not hmac.compare_digest(row['password'], password_hash(password, row['salt'])):
                        return self.send_json({'error': 'Invalid email or password.'}, 401)
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = {'tenant': row['id'], 'email': email, 'name': row['name'], 'expires': time.time() + 28800, 'connection': None}
                secure = '; Secure' if os.environ.get('COOKIE_SECURE') == '1' else ''
                return self.send_json({'ok': True}, cookie='session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800' + secure)
            if not session:
                return self.send_json({'error': 'Please sign in.'}, 401)
            tenant = session['tenant']
            if path == '/api/session' and self.command == 'GET':
                return self.send_json({k: session[k] for k in ('email', 'name')} | {'mode': 'live' if session['connection'] else 'demo', 'host': session['connection']['host'] if session['connection'] else 'demo.cyrus.local'})
            if self.command == 'POST' and path == '/api/logout':
                for key, value in list(SESSIONS.items()):
                    if value is session:
                        del SESSIONS[key]
                return self.send_json({'ok': True}, cookie='session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
            if self.command == 'POST' and path == '/api/connect':
                if data.get('demo'):
                    session['connection'] = None
                else:
                    host = str(data.get('host', '')).strip()
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.\-]*', host):
                        raise ValueError('Enter a hostname or IPv4 address without a URL scheme.')
                    allowed = [h.strip().lower() for h in os.environ.get('CYRUS_ALLOWED_HOSTS', '').split(',') if h.strip()]
                    if allowed and host.lower() not in allowed:
                        raise ValueError('This host is not in the deployment’s CYRUS_ALLOWED_HOSTS list.')
                    config = {'host': host, 'port': int(data.get('port', 993)), 'username': str(data.get('username', '')), 'password': str(data.get('password', ''))}
                    if not 1 <= config['port'] <= 65535 or not config['username'] or not config['password']:
                        raise ValueError('An admin username, password, and valid port are required.')
                    client = Cyrus(config)
                    client.list()
                    session['connection'] = config
                return self.send_json({'ok': True})
            if session['connection']:
                client = Cyrus(session['connection'])
            if self.command == 'GET' and path == '/api/mailboxes':
                with db() as c:
                    rows = client.list() if client else [dict(x) | {'delimiter': '.'} for x in c.execute('SELECT name,quota,used FROM mailboxes WHERE tenant=? ORDER BY name', (tenant,))]
                return self.send_json({'items': rows})
            if self.command == 'GET' and path == '/api/events':
                with db() as c:
                    rows = [dict(x) for x in c.execute('SELECT action,target,created FROM events WHERE tenant=? ORDER BY id DESC LIMIT 30', (tenant,))]
                return self.send_json({'items': rows})
            if self.command != 'POST':
                return self.send_json({'error': 'Not found.'}, 404)
            name = data.get('name', '')
            quoted(name)
            with db() as c:
                if not client and path != '/api/create' and not c.execute('SELECT 1 FROM mailboxes WHERE tenant=? AND name=?', (tenant, name)).fetchone():
                    raise ValueError('Mailbox not found. Refresh and try again.')
                if path == '/api/acl':
                    rows = client.acl(name) if client else [dict(x) for x in c.execute('SELECT principal,rights FROM acls WHERE tenant=? AND mailbox=? ORDER BY principal', (tenant, name))]
                    return self.send_json({'items': rows})
                if path == '/api/quota-info':
                    quota = client.quota(name) if client else dict(c.execute('SELECT quota,used FROM mailboxes WHERE tenant=? AND name=?', (tenant, name)).fetchone())
                    return self.send_json(quota)
                if path == '/api/create':
                    if client:
                        client.check(client.client.create(quoted(name)))
                    else:
                        try:
                            c.execute('INSERT INTO mailboxes VALUES(?,?,?,0)', (tenant, name, 2048))
                        except sqlite3.IntegrityError:
                            raise ValueError('A mailbox with this name already exists.')
                elif path == '/api/rename':
                    new = data.get('newName', '')
                    quoted(new)
                    if new == name:
                        raise ValueError('Choose a different mailbox name.')
                    if client:
                        client.check(client.client.rename(quoted(name), quoted(new)))
                    else:
                        rows = c.execute('SELECT name FROM mailboxes WHERE tenant=?', (tenant,)).fetchall()
                        mapping = [(r['name'], new + r['name'][len(name):]) for r in rows if r['name'] == name or r['name'].startswith(name + '.')]
                        existing = {r['name'] for r in rows}
                        if any(dest in existing for _, dest in mapping):
                            raise ValueError('The destination or a child mailbox already exists.')
                        if new.startswith(name + '.'):
                            raise ValueError('Cannot move a mailbox inside itself.')
                        for old, dest in mapping:
                            c.execute('UPDATE mailboxes SET name=? WHERE tenant=? AND name=?', (dest, tenant, old))
                            c.execute('UPDATE acls SET mailbox=? WHERE tenant=? AND mailbox=?', (dest, tenant, old))
                elif path == '/api/delete':
                    if data.get('confirmation') != name:
                        raise ValueError('Type the exact mailbox name to confirm deletion.')
                    if client:
                        client.check(client.client.delete(quoted(name)))
                    else:
                        children = [r['name'] for r in c.execute('SELECT name FROM mailboxes WHERE tenant=?', (tenant,)) if r['name'].startswith(name + '.')]
                        if children:
                            raise ValueError('Delete child mailboxes first: ' + ', '.join(children))
                        c.execute('DELETE FROM mailboxes WHERE tenant=? AND name=?', (tenant, name))
                        c.execute('DELETE FROM acls WHERE tenant=? AND mailbox=?', (tenant, name))
                elif path == '/api/quota':
                    quota = int(data.get('quota', 0))
                    if quota < 1 or quota > 104857600:
                        raise ValueError('Quota must be between 1 and 104857600 MiB.')
                    if client:
                        client.check(client.client.setquota(quoted(name), '(STORAGE %d)' % (quota * 1024)))
                    else:
                        c.execute('UPDATE mailboxes SET quota=? WHERE tenant=? AND name=?', (quota, tenant, name))
                elif path in ('/api/set-acl', '/api/delete-acl'):
                    principal = data.get('principal', '')
                    quoted(principal)
                    rights = data.get('rights', '')
                    if not isinstance(rights, str) or any(x not in RIGHTS for x in rights) or (path == '/api/set-acl' and not rights):
                        raise ValueError('Select valid IMAP access rights.')
                    if client:
                        if path == '/api/set-acl':
                            client.check(client.client.setacl(quoted(name), quoted(principal), quoted(rights)))
                        else:
                            client.check(client.client.deleteacl(quoted(name), quoted(principal)))
                    elif path == '/api/set-acl':
                        c.execute('INSERT OR REPLACE INTO acls VALUES(?,?,?,?)', (tenant, name, principal, rights))
                    else:
                        c.execute('DELETE FROM acls WHERE tenant=? AND mailbox=? AND principal=?', (tenant, name, principal))
                else:
                    return self.send_json({'error': 'Not found.'}, 404)
                mode = 'live' if client else 'demo'
                c.execute('INSERT INTO events(tenant,action,target,created) VALUES(?,?,?,?)', (tenant, mode + ':' + path.removeprefix('/api/'), name, int(time.time())))
            return self.send_json({'ok': True})
        except (ValueError, TypeError, imaplib.IMAP4.error, OSError) as exc:
            self.send_json({'error': str(exc)}, 400)
        except Exception:
            self.send_json({'error': 'Unexpected server error. Check server logs.'}, 500)
            import traceback
            traceback.print_exc()
        finally:
            if client:
                client.close()


if __name__ == '__main__':
    initialize()
    server = ThreadingHTTPServer((os.environ.get('HOST', '127.0.0.1'), int(os.environ.get('PORT', '8000'))), Handler)
    print('Cyrus Console listening on port %s' % server.server_port, flush=True)
    server.serve_forever()
