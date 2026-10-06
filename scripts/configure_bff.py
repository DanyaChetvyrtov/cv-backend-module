#!/usr/bin/env python3
"""Idempotently configure the BFF client in an existing demo realm; never reset users."""

import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(url, method="GET", token=None, body=None, form=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    else:
        data = None
    try:
        with http.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=15) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        # Do not print token responses, client secrets or request bodies.
        raise RuntimeError(f"Keycloak configuration failed: {method} {url}: HTTP {error.code}") from error


def configure(base, realm_name, public_url, secret):
    template = json.loads((Path(__file__).resolve().parents[1] / "keycloak" / "demo-realm.json").read_text())
    token = request(base + "/realms/master/protocol/openid-connect/token", method="POST", form={
        "client_id": "admin-cli", "grant_type": "password",
        "username": os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin"),
        "password": os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin"),
    })["access_token"]
    realm_url = base + "/admin/realms/" + urllib.parse.quote(realm_name, safe="")

    def admin(path="", method="GET", body=None):
        return request(realm_url + path, method=method, token=token, body=body)

    def find_client(name):
        matches = admin("/clients?clientId=" + urllib.parse.quote(name, safe=""))
        if len(matches) > 1:
            raise RuntimeError("Ambiguous client: " + name)
        return admin("/clients/" + matches[0]["id"]) if matches else None

    api = find_client("demo-api")
    if not api:
        raise RuntimeError("Expected demo-api in the imported demo realm")
    roles = [admin("/clients/" + api["id"] + "/roles/" + role) for role in ("USER", "ADMIN")]
    desired = next(client for client in template["clients"] if client["clientId"] == "demo-bff")
    desired["secret"] = secret
    desired["redirectUris"] = [public_url + "/api/auth/callback/keycloak"]
    desired["attributes"]["post.logout.redirect.uris"] = public_url + "/"
    existing = find_client("demo-bff")
    if existing:
        mapper_ids = {mapper["name"]: mapper["id"] for mapper in existing.get("protocolMappers", [])}
        for mapper in desired.get("protocolMappers", []):
            if mapper["name"] in mapper_ids:
                mapper["id"] = mapper_ids[mapper["name"]]
        desired["id"] = existing["id"]
        admin("/clients/" + existing["id"], "PUT", desired)
    else:
        admin("/clients", "POST", desired)
    bff = find_client("demo-bff")
    admin("/clients/" + bff["id"] + "/scope-mappings/clients/" + api["id"], "POST", roles)

    for name in ("demo-browser", "demo-cli"):
        legacy = find_client(name)
        if legacy and legacy.get("enabled"):
            legacy["enabled"] = False
            admin("/clients/" + legacy["id"], "PUT", legacy)

    groups = admin("/groups?search=demo-users&exact=true")
    group = next((item for item in groups if item["name"] == "demo-users"), None)
    if not group:
        admin("/groups", "POST", {"name": "demo-users"})
        group = next(item for item in admin("/groups?search=demo-users&exact=true") if item["name"] == "demo-users")
    mapping = "/groups/" + group["id"] + "/role-mappings/clients/" + api["id"]
    mapped = admin(mapping)
    if any(role["name"] != "USER" for role in mapped):
        raise RuntimeError("demo-users has unexpected roles; refusing to give them to new registrations")
    admin(mapping, "POST", [next(role for role in roles if role["name"] == "USER")])
    admin("/default-groups/" + group["id"], "PUT")
    realm = admin()
    realm_changed = False
    desired_realm = {
        "registrationAllowed": True,
        "loginTheme": "cv-access",
        "internationalizationEnabled": True,
        "supportedLocales": ["ru", "en"],
        "defaultLocale": "ru",
        "displayName": "CV Access",
    }
    for key, value in desired_realm.items():
        if realm.get(key) != value:
            realm[key] = value
            realm_changed = True
    if realm_changed:
        admin(method="PUT", body=realm)
    print("BFF client, PKCE, role scopes, registration and CV Access theme configured; existing users preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-url", default=os.getenv("KEYCLOAK_URL", "http://localhost:8081"))
    parser.add_argument("--realm", default="demo")
    args = parser.parse_args()
    public_url = os.getenv("BFF_PUBLIC_URL", "http://127.0.0.1:5173").rstrip("/")
    secret = os.getenv("KEYCLOAK_CLIENT_SECRET", "local-bff-secret")
    if not secret:
        raise SystemExit("KEYCLOAK_CLIENT_SECRET must not be empty")
    configure(args.keycloak_url.rstrip("/"), args.realm, public_url, secret)


if __name__ == "__main__":
    main()
