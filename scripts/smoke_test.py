#!/usr/bin/env python3
"""Exercise the full BFF through its public web origin with a real Keycloak and CV (Pillow is needed for employee face tests)."""

import argparse
import http.cookiejar
import json
import os
import secrets
from pathlib import Path
import struct
import urllib.error
import urllib.parse
import urllib.request
import zlib
from html.parser import HTMLParser


class BrowserReturn(Exception):
    pass


class CaptureReturn(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if newurl.startswith(self.origin + "/") and parsed.path == "/":
            if urllib.parse.parse_qs(parsed.query).get("auth") == ["error"]:
                raise SystemExit("BFF rejected the OIDC callback")
            raise BrowserReturn(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LocalhostCookies(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):
        if request.type == "http" and urllib.parse.urlsplit(request.full_url).hostname in ("localhost", "127.0.0.1"):
            return True
        return super().return_ok_secure(cookie, request)


class Form(HTMLParser):
    def __init__(self, expected):
        super().__init__()
        self.expected = expected
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == self.expected:
            self.action = attrs.get("action")


def send(client, url, expected=200, data=None, headers=None, method=None):
    try:
        with client.open(urllib.request.Request(url, data=data, headers=headers or {}, method=method), timeout=130) as response:
            status, body, response_headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        status, body, response_headers = error.code, error.read(), error.headers
    if status != expected:
        # Avoid printing token/client credential responses on a failed test.
        raise SystemExit(f"FAIL {urllib.parse.urlsplit(url).path}: expected HTTP {expected}, got {status}")
    return body, response_headers


def blank_png():
    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", 64, 64, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress((b"\x00" + b"\x00\x00\x00" * 64) * 64)) + chunk(b"IEND", b""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-url", default="http://127.0.0.1:5173")
    parser.add_argument("--keycloak-url", default="http://localhost:8081")
    parser.add_argument("--face-image", default=os.getenv("CV_FACE_TEST_IMAGE"))
    parser.add_argument("--persistence-state")
    parser.add_argument("--verify-persistence", action="store_true")
    args = parser.parse_args()
    if args.verify_persistence and not (args.persistence_state and args.face_image):
        parser.error("--verify-persistence needs --persistence-state and --face-image")
    web, keycloak = args.web_url.rstrip("/"), args.keycloak_url.rstrip("/")
    plain = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    token_body, _ = send(plain, keycloak + "/realms/master/protocol/openid-connect/token", data=urllib.parse.urlencode({
        "client_id": "admin-cli", "grant_type": "password", "username": os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin"),
        "password": os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin"),
    }).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    admin_token = json.loads(token_body)["access_token"]

    def admin(path, method="GET", body=None, expected=200):
        payload, _ = send(plain, keycloak + "/admin/realms/demo" + path, expected=expected, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + admin_token, "Content-Type": "application/json"})
        return json.loads(payload) if payload else None

    bff_clients = admin("/clients?clientId=demo-bff")
    if len(bff_clients) != 1:
        raise SystemExit("Expected exactly one confidential BFF client")
    client_path = "/clients/" + bff_clients[0]["id"]
    representation = admin(client_path)
    if representation.get("publicClient") or representation.get("directAccessGrantsEnabled"):
        raise SystemExit("The BFF client must be confidential without password grants")
    for legacy in ("demo-browser", "demo-cli"):
        if any(client.get("enabled") for client in admin("/clients?clientId=" + legacy)):
            raise SystemExit("Legacy browser/password-grant client is still enabled")
    previous_lifespan = representation.get("attributes", {}).get("access.token.lifespan")
    # Spring refreshes tokens with <=60s remaining: exercise real server refresh without a long sleep.
    representation.setdefault("attributes", {})["access.token.lifespan"] = "60"
    admin(client_path, "PUT", representation, expected=204)
    temporary_user = None
    created_employee = None
    keep_employee = False

    def browser():
        jar = http.cookiejar.CookieJar(policy=LocalhostCookies())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), CaptureReturn(web))
        return opener, jar

    def api(client, path, expected=200, **kwargs):
        body, headers = send(client, web + path, expected=expected, **kwargs)
        print(f"PASS HTTP {expected}: {path}")
        return body, headers

    def csrf(client):
        body, _ = api(client, "/api/auth/csrf")
        return json.loads(body)

    def authorize(client, jar, username, password, register=False):
        starter = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), NoRedirect())
        _, headers = send(starter, web + ("/api/auth/register" if register else "/api/auth/login"), expected=302)
        authorization_url = urllib.parse.urljoin(web + "/", headers["Location"])
        assert authorization_url.startswith(web + "/api/auth/authorize/")
        _, headers = send(starter, authorization_url, expected=302)
        location = headers["Location"]
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        assert params["client_id"] == ["demo-bff"]
        assert params["redirect_uri"] == [web + "/api/auth/callback/keycloak"]
        assert params["code_challenge_method"] == ["S256"]
        assert params.get("state") and params.get("nonce")
        assert "client_secret" not in params and "code_verifier" not in params
        form_body, _ = send(client, location)
        form = Form("kc-register-form" if register else "kc-form-login")
        form.feed(form_body.decode())
        if not form.action:
            raise SystemExit("Keycloak did not return the requested form")
        values = {"username": username, "password": password}
        if register:
            values.update({"email": username + "@example.test", "firstName": "BFF", "lastName": "Test", "password-confirm": password})
        else:
            values["credentialId"] = ""
        try:
            send(client, form.action, data=urllib.parse.urlencode(values).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        except BrowserReturn:
            pass
        else:
            raise SystemExit("Keycloak/BFF did not return to the UI")
        cookies = [cookie for cookie in jar if cookie.name == "BFFSESSION"]
        assert len(cookies) == 1 and cookies[0].has_nonstandard_attr("HttpOnly")
        assert cookies[0].get_nonstandard_attr("SameSite", "").lower() == "lax"
        body, _ = api(client, "/api/me")
        profile = json.loads(body)
        assert profile["username"] == username
        assert not any("token" in field.lower() or "secret" in field.lower() for field in profile)
        api(client, "/api/me")  # A reload/repeated request keeps the server session.
        return profile

    def logout(client):
        value = csrf(client)
        try:
            send(client, web + "/api/auth/logout", data=urllib.parse.urlencode({value["parameterName"]: value["token"]}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
        except BrowserReturn:
            pass
        else:
            raise SystemExit("OIDC logout did not return to the UI")
        api(client, "/api/me", expected=401)

    def employee_request(client, path, image=None, fields=None, method="POST", expected=200, include_csrf=True):
        headers = {}
        if include_csrf:
            value = csrf(client)
            headers[value["headerName"]] = value["token"]
        data = None
        if image is not None:
            boundary = "employee-smoke-boundary"
            chunks = []
            for key, text in (fields or {}).items():
                chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{text}\r\n').encode())
            chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="image"; filename="photo.png"\r\nContent-Type: image/png\r\n\r\n').encode() + image + b"\r\n")
            chunks.append(f"--{boundary}--\r\n".encode())
            data = b"".join(chunks)
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        body, _ = api(client, path, expected=expected, method=method, data=data, headers=headers)
        return json.loads(body) if body else None

    def face_photos():
        from io import BytesIO
        from PIL import Image
        photo = Path(args.face_image).read_bytes()
        source = Image.open(BytesIO(photo)).convert("RGB")
        query = BytesIO()
        source.resize((460, 460)).save(query, format="JPEG", quality=90)
        many = Image.new("RGB", (source.width * 2, source.height))
        many.paste(source, (0, 0))
        many.paste(source, (source.width, 0))
        output = BytesIO()
        many.save(output, format="PNG")
        return photo, query.getvalue(), output.getvalue()

    try:
        if args.verify_persistence:
            state = json.loads(Path(args.persistence_state).read_text())
            assert state["employeeCode"].startswith("SMOKE-")
            created_employee = state["id"]
            manager, manager_jar = browser()
            authorize(manager, manager_jar, "manager", "manager123")
            listing, _ = api(manager, "/api/employees?size=100")
            assert any(item["id"] == state["id"] and item["employeeCode"] == state["employeeCode"] for item in json.loads(listing)["items"])
            _, query_photo, _ = face_photos()
            result = employee_request(manager, "/api/employees/identifications", image=query_photo)
            assert result["status"] == "matched" and result["employee"]["id"] == state["id"]
            employee_request(manager, "/api/employees/" + state["id"], method="DELETE", expected=204)
            created_employee = None
            result = employee_request(manager, "/api/employees/identifications", image=query_photo)
            assert result["status"] == "unknown" and result["employee"] is None
            logout(manager)
            print("PASS employee data/templates survive BFF and CV restart; deletion removes recognition")
            return
        html, _ = send(plain, web + "/")
        assert b'<div id="root">' in html and b"/assets/" in html
        public, _ = api(plain, "/api/public")
        assert "issuerUri" not in json.loads(public)
        health, _ = api(plain, "/api/health")
        assert json.loads(health)["status"] == "ok"
        for endpoint in ("me", "user", "admin", "employees"):
            api(plain, "/api/" + endpoint, expected=401)
        api(plain, "/api/me", expected=401, headers={"Authorization": "Bearer browser-token-is-not-accepted"})
        anonymous, _ = browser()
        user, user_jar = browser()
        profile = authorize(user, user_jar, "demo", "demo123")
        assert profile["roles"] == ["USER"]
        api(user, "/api/user")
        api(user, "/api/admin", expected=403)
        api(user, "/api/auth/logout", expected=403, data=b"")
        logout(user)
        manager, manager_jar = browser()
        profile = authorize(manager, manager_jar, "manager", "manager123")
        assert set(profile["roles"]) == {"USER", "ADMIN"}
        api(manager, "/api/admin")
        if args.face_image:
            photo, query_photo, many_photo = face_photos()
            fields = {"employeeCode": "SMOKE-" + secrets.token_hex(8).upper(), "fullName": "BFF Smoke Worker", "department": "Integration"}
            employee_request(manager, "/api/employees", image=photo, fields=fields, expected=403, include_csrf=False)
            ordinary, ordinary_jar = browser()
            authorize(ordinary, ordinary_jar, "demo", "demo123")
            employee_request(ordinary, "/api/employees", image=photo, fields=fields, expected=403)
            api(ordinary, "/api/employees", expected=403)
            before = employee_request(manager, "/api/employees/identifications", image=photo)
            assert before["status"] == "unknown"
            employee = employee_request(manager, "/api/employees", image=photo, fields=fields, expected=201)
            created_employee = employee["id"]
            assert employee["employeeCode"] == fields["employeeCode"] and "embedding" not in employee
            listing, _ = api(manager, "/api/employees?size=100")
            assert "embedding" not in listing.decode() and any(item["id"] == created_employee for item in json.loads(listing)["items"])
            result = employee_request(ordinary, "/api/employees/identifications", image=query_photo)
            assert result["status"] == "matched" and result["employee"]["id"] == created_employee
            assert result["similarity"] > result["threshold"]
            employee_request(manager, "/api/employees", image=photo, fields={**fields, "employeeCode": fields["employeeCode"] + "-DUP"}, expected=409)
            for invalid_photo in (blank_png(), many_photo):
                employee_request(manager, "/api/employees", image=invalid_photo, fields=fields, expected=422)
                employee_request(ordinary, "/api/employees/identifications", image=invalid_photo, expected=422)
            employee_request(ordinary, "/api/employees/" + created_employee, method="DELETE", expected=403)
            employee_request(manager, "/api/employees/" + created_employee, method="DELETE", expected=403, include_csrf=False)
            employee_request(manager, "/api/employees/" + created_employee, method="DELETE", expected=204)
            created_employee = None
            result = employee_request(ordinary, "/api/employees/identifications", image=query_photo)
            assert result["status"] == "unknown" and result["employee"] is None
            if args.persistence_state:
                employee = employee_request(manager, "/api/employees", image=photo, fields=fields, expected=201)
                created_employee = employee["id"]
                Path(args.persistence_state).write_text(json.dumps({"id": created_employee, "employeeCode": employee["employeeCode"]}))
                keep_employee = True
            logout(ordinary)
            print("PASS employee enrollment, real face recognition, unknown face, duplicate prevention, invalid photos, ADMIN/USER and deletion")
        else:
            print("SKIP employee recognition: provide --face-image and install Pillow")
        logout(manager)
        temporary_user = "bff-smoke-" + secrets.token_hex(8)
        registered, registered_jar = browser()
        profile = authorize(registered, registered_jar, temporary_user, "Demo123!", register=True)
        assert profile["roles"] == ["USER"]
        api(registered, "/api/user")
        api(registered, "/api/admin", expected=403)
        matches = admin("/users?username=" + temporary_user + "&exact=true")
        assert len(matches) == 1
        # Only revoke the unique account created by this test, never existing demo/user sessions.
        admin("/users/" + matches[0]["id"] + "/logout", "POST", expected=204)
        api(registered, "/api/me", expected=401)
        print("PASS BFF login, registration, cookie/CSRF, USER/ADMIN, server refresh, provider revocation, logout and face verification")
    finally:
        if created_employee and not keep_employee:
            cleaner, cleaner_jar = browser()
            authorize(cleaner, cleaner_jar, "manager", "manager123")
            employee_request(cleaner, "/api/employees/" + created_employee, method="DELETE", expected=204)
            logout(cleaner)
        if temporary_user:
            for account in admin("/users?username=" + temporary_user + "&exact=true"):
                admin("/users/" + account["id"], "DELETE", expected=204)
        current = admin(client_path)
        if previous_lifespan is None:
            current.setdefault("attributes", {}).pop("access.token.lifespan", None)
        else:
            current.setdefault("attributes", {})["access.token.lifespan"] = previous_lifespan
        admin(client_path, "PUT", current, expected=204)


if __name__ == "__main__":
    main()
