"""Offline tests for idempotent realm migration and preservation of existing users."""

import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from configure_bff import configure


class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.state = {
            "realm": {"realm": "demo", "registrationAllowed": False},
            "clients": {
                "api": {"id": "api", "clientId": "demo-api", "enabled": True},
                "browser": {"id": "browser", "clientId": "demo-browser", "enabled": True},
                "cli": {"id": "cli", "clientId": "demo-cli", "enabled": True},
            },
            "roles": {name: {"id": name.lower(), "name": name} for name in ("USER", "ADMIN")},
            "group": None, "group_roles": [], "defaults": set(), "scopes": [],
            "users": [{"username": "existing-user", "roles": ["USER"]}, {"username": "existing-manager", "roles": ["USER", "ADMIN"]}],
            "requests": [],
        }
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                uri = urlsplit(self.path)
                path = uri.path
                method = self.command
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                value = json.loads(body) if body and self.headers.get("Content-Type") == "application/json" else None
                state["requests"].append((method, path))
                result = None
                status = 200 if method == "GET" else 204
                if path == "/realms/master/protocol/openid-connect/token":
                    result, status = {"access_token": "fixture-admin"}, 200
                elif self.headers.get("Authorization") != "Bearer fixture-admin":
                    status = 401
                else:
                    relative = path.removeprefix("/admin/realms/demo")
                    parts = relative.strip("/").split("/")
                    if relative == "":
                        if method == "PUT": state["realm"] = value
                        result = state["realm"]
                    elif relative == "/clients":
                        if method == "GET":
                            name = parse_qs(uri.query).get("clientId", [None])[0]
                            result = [client for client in state["clients"].values() if client["clientId"] == name]
                        else:
                            value["id"] = "bff"
                            for mapper in value.get("protocolMappers", []): mapper["id"] = "mapper-" + mapper["name"]
                            state["clients"]["bff"] = value
                    elif parts[0] == "clients" and len(parts) == 2:
                        if method == "PUT": state["clients"][parts[1]] = value
                        result = state["clients"][parts[1]]
                    elif len(parts) == 4 and parts[2] == "roles":
                        result = state["roles"][parts[3]]
                    elif "scope-mappings" in parts:
                        state["scopes"] = value
                    elif relative == "/groups":
                        if method == "POST": state["group"] = {"id": "group", "name": "demo-users"}
                        result = [state["group"]] if state["group"] else []
                    elif "role-mappings" in parts:
                        if method == "POST": state["group_roles"] = value
                        result = state["group_roles"]
                    elif parts[0] == "default-groups":
                        state["defaults"].add(parts[1])
                    else:
                        status = 404
                data = json.dumps(result).encode() if result is not None and status == 200 else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = handle_request

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def migrate(self):
        with contextlib.redirect_stdout(io.StringIO()):
            configure(self.base, "demo", "https://app.example", "fixture-confidential-secret")

    def test_migration_is_idempotent_and_preserves_users(self):
        users = copy.deepcopy(self.state["users"])
        self.migrate()
        first = copy.deepcopy(self.state["clients"]["bff"])
        self.migrate()
        bff = self.state["clients"]["bff"]
        self.assertEqual(first, bff)
        self.assertEqual(users, self.state["users"])
        self.assertFalse(any("/users" in path or method == "DELETE" for method, path in self.state["requests"]))
        self.assertFalse(bff["publicClient"])
        self.assertFalse(bff["directAccessGrantsEnabled"])
        self.assertEqual(bff["secret"], "fixture-confidential-secret")
        self.assertEqual(bff["redirectUris"], ["https://app.example/api/auth/callback/keycloak"])
        self.assertFalse(self.state["clients"]["browser"]["enabled"])
        self.assertFalse(self.state["clients"]["cli"]["enabled"])
        self.assertEqual([role["name"] for role in self.state["group_roles"]], ["USER"])
        self.assertEqual({role["name"] for role in self.state["scopes"]}, {"USER", "ADMIN"})
        self.assertTrue(self.state["realm"]["registrationAllowed"])
        self.assertEqual(self.state["realm"]["loginTheme"], "cv-access")
        self.assertTrue(self.state["realm"]["internationalizationEnabled"])
        self.assertEqual(self.state["realm"]["supportedLocales"], ["ru", "en"])
        self.assertEqual(self.state["realm"]["defaultLocale"], "ru")
        self.assertEqual(self.state["realm"]["displayName"], "CV Access")

    def test_registration_refuses_an_elevated_default_group(self):
        self.state["group"] = {"id": "group", "name": "demo-users"}
        self.state["group_roles"] = [self.state["roles"]["ADMIN"]]
        with self.assertRaisesRegex(RuntimeError, "unexpected roles"):
            self.migrate()
        self.assertFalse(self.state["realm"]["registrationAllowed"])


if __name__ == "__main__":
    unittest.main()
