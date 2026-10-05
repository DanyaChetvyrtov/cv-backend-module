#!/usr/bin/env python3
"""Verify a running API against real Keycloak tokens using only Python's standard library."""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# Local services must bypass any HTTP proxy configured on the developer's machine.
http_client = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(url, token=None, form=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(form).encode() if form is not None else None, headers=headers
    )
    try:
        with http_client.open(req, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def wait_for(url, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if request(url)[0] == 200:
                return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    raise SystemExit(f"Service did not become ready: {url}")


def expect(url, expected, token=None):
    status, body = request(url, token)
    if status != expected:
        raise SystemExit(f"FAIL {url}: expected HTTP {expected}, got {status}: {body}")
    print(f"PASS HTTP {status}: {urllib.parse.urlsplit(url).path}")
    return json.loads(body) if body else None


def login(issuer, username, password):
    status, body = request(f"{issuer}/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "demo-cli", "scope": "openid profile email",
        "username": username, "password": password,
    })
    if status != 200:
        raise SystemExit(f"Login failed for {username}: HTTP {status}: {body}")
    return json.loads(body)


class LoginForm(HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")


class LocalhostCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):
        # Browsers treat HTTP localhost as a secure context; Python's cookie jar does not.
        if request.type == "http" and urllib.parse.urlsplit(request.full_url).hostname in ("localhost", "127.0.0.1"):
            return True
        return super().return_ok_secure(cookie, request)


def check_browser_login(api, issuer):
    """Exercise the same Authorization Code + PKCE protocol used by the demo page."""
    browser = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=LocalhostCookiePolicy())),
    )
    verifier, state = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = urllib.parse.urlencode({
        "client_id": "demo-browser", "redirect_uri": f"{api}/", "response_type": "code",
        "scope": "openid profile email", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    with browser.open(f"{issuer}/protocol/openid-connect/auth?{params}", timeout=10) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    if not form.action:
        raise SystemExit("Keycloak browser login form was not returned")
    with browser.open(form.action, data=urllib.parse.urlencode({
        "username": "demo", "password": "demo123", "credentialId": "",
    }).encode(), timeout=10) as response:
        callback = urllib.parse.urlsplit(response.url)
    query = urllib.parse.parse_qs(callback.query)
    if query.get("state") != [state] or "code" not in query:
        raise SystemExit("Authorization Code callback or state validation failed")
    if query.get("iss") not in (None, [issuer]):
        raise SystemExit("Unexpected callback issuer")
    req = urllib.request.Request(f"{issuer}/protocol/openid-connect/token", headers={
        "Origin": api, "Content-Type": "application/x-www-form-urlencoded",
    }, data=urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": "demo-browser", "redirect_uri": f"{api}/",
        "code": query["code"][0], "code_verifier": verifier,
    }).encode())
    with browser.open(req, timeout=10) as response:
        if response.headers.get("Access-Control-Allow-Origin") != api:
            raise SystemExit("Token endpoint did not permit the demo browser origin")
        tokens = json.load(response)
    expect(f"{api}/api/me", 200, tokens["access_token"])
    expect(f"{api}/api/admin", 403, tokens["access_token"])
    logout_params = urllib.parse.urlencode({
        "client_id": "demo-browser", "id_token_hint": tokens["id_token"], "post_logout_redirect_uri": f"{api}/",
    })
    with browser.open(f"{issuer}/protocol/openid-connect/logout?{logout_params}", timeout=10) as response:
        if response.url != f"{api}/":
            raise SystemExit("Browser logout did not return to the demo page")
    # With the SSO cookie invalidated, another authorization request must show the login form.
    with browser.open(f"{issuer}/protocol/openid-connect/auth?{params}", timeout=10) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    if not form.action:
        raise SystemExit("Browser logout did not end the Keycloak SSO session")
    print("PASS browser Authorization Code + PKCE, CORS and SSO logout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://localhost:8080")
    parser.add_argument("--issuer", default="http://localhost:8081/realms/demo")
    parser.add_argument("--wait", type=int, default=180, help="Startup timeout in seconds")
    args = parser.parse_args()
    api, issuer = args.api.rstrip("/"), args.issuer.rstrip("/")
    wait_for(f"{issuer}/.well-known/openid-configuration", args.wait)
    wait_for(f"{api}/actuator/health", args.wait)

    expect(f"{api}/api/public", 200)
    for endpoint in ("me", "user", "admin"):
        expect(f"{api}/api/{endpoint}", 401)
    expect(f"{api}/api/me", 401, "not-a-jwt")

    user = login(issuer, "demo", "demo123")
    profile = expect(f"{api}/api/me", 200, user["access_token"])
    if profile["username"] != "demo" or profile["roles"] != ["USER"]:
        raise SystemExit(f"Unexpected demo profile: {profile}")
    expect(f"{api}/api/user", 200, user["access_token"])
    expect(f"{api}/api/admin", 403, user["access_token"])
    # An ID token targets the CLI client, not this resource server.
    expect(f"{api}/api/me", 401, user["id_token"])

    manager = login(issuer, "manager", "manager123")
    profile = expect(f"{api}/api/me", 200, manager["access_token"])
    if profile["username"] != "manager" or profile["roles"] != ["ADMIN", "USER"]:
        raise SystemExit(f"Unexpected manager profile: {profile}")
    expect(f"{api}/api/user", 200, manager["access_token"])
    expect(f"{api}/api/admin", 200, manager["access_token"])

    status, body = request(f"{issuer}/protocol/openid-connect/token", form={
        "grant_type": "refresh_token", "client_id": "demo-cli", "refresh_token": user["refresh_token"],
    })
    if status != 200:
        raise SystemExit(f"Refresh failed: HTTP {status}: {body}")
    refreshed = json.loads(body)
    expect(f"{api}/api/me", 200, refreshed["access_token"])

    status, body = request(f"{issuer}/protocol/openid-connect/logout", form={
        "client_id": "demo-cli", "refresh_token": refreshed["refresh_token"],
    })
    if status != 204:
        raise SystemExit(f"Logout failed: HTTP {status}: {body}")
    status, _ = request(f"{issuer}/protocol/openid-connect/token", form={
        "grant_type": "refresh_token", "client_id": "demo-cli", "refresh_token": refreshed["refresh_token"],
    })
    if status != 400:
        raise SystemExit(f"Refresh after logout should fail with HTTP 400, got {status}")
    print("PASS token refresh and logout invalidate the refresh session")
    check_browser_login(api, issuer)
    print("All smoke checks passed.")


if __name__ == "__main__":
    main()
