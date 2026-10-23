import http.cookiejar
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class ApplicationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        server.DB = Path(cls.temp.name) / 'test.db'
        server.initialize()
        cls.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.base = 'http://127.0.0.1:' + str(cls.http.server_port)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.email = server.secrets.token_hex(5) + '@example.com'

    def request(self, path, data=None, client=None, headers=None):
        req = urllib.request.Request(self.base + '/api/' + path, data=json.dumps(data).encode() if data is not None else None, headers=headers or ({'Content-Type': 'application/json'} if data is not None else {}))
        try:
            with (client or self.client).open(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def register(self):
        self.assertEqual(self.request('register', {'name': 'Test workspace', 'email': self.email, 'password': 'secure password 123'})[0], 200)

    def test_authentication_and_logout(self):
        self.assertEqual(self.request('mailboxes')[0], 401)
        self.register()
        self.assertEqual(self.request('session')[1]['email'], self.email)
        self.assertEqual(self.request('logout', {})[0], 200)
        self.assertEqual(self.request('session')[0], 401)
        self.assertEqual(self.request('login', {'email': self.email, 'password': 'wrong password'})[0], 401)
        self.assertEqual(self.request('login', {'email': self.email, 'password': 'secure password 123'})[0], 200)

    def test_mailbox_lifecycle_and_acl(self):
        self.register()
        self.assertEqual(len(self.request('mailboxes')[1]['items']), 8)
        self.assertEqual(self.request('create', {'name': 'user.casey'})[0], 200)
        self.assertEqual(self.request('create', {'name': 'user.casey'})[0], 400)
        self.assertEqual(self.request('create', {'name': 'user.casey.Archive'})[0], 200)
        self.assertEqual(self.request('quota', {'name': 'user.casey', 'quota': 8192})[0], 200)
        self.assertEqual(self.request('quota-info', {'name': 'user.casey'})[1]['quota'], 8192)
        self.assertEqual(self.request('set-acl', {'name': 'user.casey', 'principal': 'team', 'rights': 'lr'})[0], 200)
        self.assertEqual(self.request('acl', {'name': 'user.casey'})[1]['items'], [{'principal': 'team', 'rights': 'lr'}])
        self.assertEqual(self.request('set-acl', {'name': 'user.casey', 'principal': 'team', 'rights': 'invalid'})[0], 400)
        self.assertEqual(self.request('rename', {'name': 'user.casey', 'newName': 'user.renamed'})[0], 200)
        names = [x['name'] for x in self.request('mailboxes')[1]['items']]
        self.assertIn('user.renamed.Archive', names)
        self.assertEqual(self.request('acl', {'name': 'user.renamed'})[1]['items'][0]['principal'], 'team')
        self.assertEqual(self.request('delete', {'name': 'user.renamed', 'confirmation': 'wrong'})[0], 400)
        self.assertEqual(self.request('delete', {'name': 'user.renamed', 'confirmation': 'user.renamed'})[0], 400)
        self.assertEqual(self.request('delete-acl', {'name': 'user.renamed', 'principal': 'team'})[0], 200)
        self.assertEqual(self.request('acl', {'name': 'user.renamed'})[1]['items'], [])
        for name in ('user.renamed.Archive', 'user.renamed'):
            self.assertEqual(self.request('delete', {'name': name, 'confirmation': name})[0], 200)
        self.assertGreater(len(self.request('events')[1]['items']), 5)

    def test_tenant_isolation(self):
        self.register()
        self.request('create', {'name': 'shared.private'})
        other = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.assertEqual(self.request('register', {'name': 'Other', 'email': 'other-' + self.email, 'password': 'another password 123'}, client=other)[0], 200)
        self.assertNotIn('shared.private', [x['name'] for x in self.request('mailboxes', client=other)[1]['items']])
        self.assertEqual(self.request('acl', {'name': 'shared.private'}, client=other)[0], 400)
        self.assertEqual(self.request('delete', {'name': 'shared.private', 'confirmation': 'shared.private'}, client=other)[0], 400)
        self.assertEqual(self.request('events', client=other)[1]['items'], [])

    def test_input_validation_and_cross_origin(self):
        self.register()
        for name in ('', 'mail\r\nDELETE user.alex', 'é'):
            self.assertEqual(self.request('create', {'name': name})[0], 400)
        self.assertEqual(self.request('create', {'name': 'shared.cross'}, headers={'Content-Type': 'application/json', 'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request('connect', {'host': 'https://example.com', 'port': 993, 'username': 'admin', 'password': 'secret'})[0], 400)


class CyrusAdapterTest(unittest.TestCase):
    def test_verified_tls_and_parsing(self):
        fake = MagicMock()
        fake.capabilities = (b'IMAP4rev1', b'ACL', b'QUOTA')
        fake.login.return_value = ('OK', [b'Logged in'])
        fake.list.return_value = ('OK', [b'(\\HasNoChildren) "." "user.alex"', b'(\\Noselect) "." "user"', b'(\\HasNoChildren) "/" shared/support'])
        fake.getacl.return_value = ('OK', [b'"user.alex" alex lrswipkxtecdan "support team" lr'])
        fake.getquotaroot.return_value = ('OK', [[b'"user.alex" "user.alex"'], [b'"user.alex" (STORAGE 1024 2097152)']])
        with patch.object(server.imaplib, 'IMAP4_SSL', return_value=fake) as factory:
            client = server.Cyrus({'host': 'mail.example.com', 'port': 993, 'username': 'admin', 'password': 'secret'})
            context = factory.call_args.kwargs['ssl_context']
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, server.ssl.CERT_REQUIRED)
            self.assertEqual([m['name'] for m in client.list()], ['user.alex', 'shared/support'])
            self.assertEqual(client.acl('user.alex')[1], {'principal': 'support team', 'rights': 'lr'})
            self.assertEqual(client.quota('user.alex'), {'used': 1, 'quota': 2048})
            client.close()
            fake.logout.assert_called_once()

    def test_protocol_injection_and_escaping(self):
        with self.assertRaises(ValueError):
            server.quoted('mailbox\nDELETE')
        self.assertEqual(server.quoted('a"b'), '"a\\"b"')
        self.assertEqual(server.tokens(b'"a\\"b" anyone lr'), ['a"b', 'anyone', 'lr'])


if __name__ == '__main__':
    unittest.main()
