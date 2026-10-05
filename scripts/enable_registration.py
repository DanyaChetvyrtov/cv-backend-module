#!/usr/bin/env python3
"""Update an existing local demo realm for registration and the React client."""

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request


http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(url, method="GET", token=None, body=None, form=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    else:
        data = None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with http.open(req, timeout=10) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"{method} {url}: HTTP {error.code}: {detail}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-url", default="http://localhost:8081")
    parser.add_argument("--realm", default="demo")
    args = parser.parse_args()

    base = args.keycloak_url.rstrip("/")
    realm_name = urllib.parse.quote(args.realm, safe="")
    admin_token = request(f"{base}/realms/master/protocol/openid-connect/token", method="POST", form={
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin"),
        "password": os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin"),
    })["access_token"]
    admin_url = f"{base}/admin/realms/{realm_name}"

    def admin(path="", method="GET", body=None):
        return request(f"{admin_url}{path}", method=method, token=admin_token, body=body)

    clients = admin("/clients?clientId=demo-api")
    if len(clients) != 1:
        raise RuntimeError("Client demo-api was not found in the realm")
    client_id = clients[0]["id"]
    user_role = admin(f"/clients/{client_id}/roles/USER")

    groups = admin("/groups?search=demo-users&exact=true")
    group = next((item for item in groups if item["name"] == "demo-users"), None)
    if group is None:
        admin("/groups", method="POST", body={"name": "demo-users"})
        groups = admin("/groups?search=demo-users&exact=true")
        group = next(item for item in groups if item["name"] == "demo-users")

    group_id = group["id"]
    mapping_path = f"/groups/{group_id}/role-mappings/clients/{client_id}"
    mapped_roles = admin(mapping_path)
    if any(role["name"] != "USER" for role in mapped_roles):
        raise RuntimeError("demo-users has unexpected demo-api roles; check it before enabling registration")
    if not any(role["name"] == "USER" for role in mapped_roles):
        admin(mapping_path, method="POST", body=[user_role])

    default_groups = admin("/default-groups")
    if not any(item["id"] == group_id for item in default_groups):
        admin(f"/default-groups/{group_id}", method="PUT")

    realm = admin()
    if not realm.get("registrationAllowed"):
        realm["registrationAllowed"] = True
        admin(method="PUT", body=realm)

    browser_clients = admin("/clients?clientId=demo-browser")
    if len(browser_clients) != 1:
        raise RuntimeError("Client demo-browser was not found in the realm")
    browser_id = browser_clients[0]["id"]
    browser_client = admin(f"/clients/{browser_id}")
    browser_client["redirectUris"] = ["http://127.0.0.1:5173/"]
    browser_client["webOrigins"] = ["http://127.0.0.1:5173"]
    browser_client.setdefault("attributes", {})["post.logout.redirect.uris"] = "http://127.0.0.1:5173/"
    admin(f"/clients/{browser_id}", method="PUT", body=browser_client)
    print(f"Registration and CV Web redirect are configured for {args.realm}; existing users are preserved.")


if __name__ == "__main__":
    main()
