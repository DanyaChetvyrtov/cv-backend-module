"use strict";

const statusElement = document.querySelector("#status");
const resultElement = document.querySelector("#result");
const loginButton = document.querySelector("#login");
const logoutButton = document.querySelector("#logout");
let config;
let accessToken;
let idToken;
const redirectUri = `${window.location.origin}/`;

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomString() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function login() {
  const verifier = randomString();
  const state = randomString();
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  sessionStorage.setItem("keycloak-pkce", JSON.stringify({ verifier, state, createdAt: Date.now() }));
  const url = new URL(`${config.issuerUri}/protocol/openid-connect/auth`);
  url.search = new URLSearchParams({
    client_id: config.browserClientId, redirect_uri: redirectUri, response_type: "code",
    scope: "openid profile email", state, code_challenge: challenge, code_challenge_method: "S256",
  });
  window.location.assign(url);
}

async function finishLogin() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has("code") && !params.has("error")) return;
  // Remove the one-time code from browser history before any other API calls.
  window.history.replaceState({}, "", "/");
  const saved = sessionStorage.getItem("keycloak-pkce");
  sessionStorage.removeItem("keycloak-pkce");
  const pending = saved ? JSON.parse(saved) : null;
  if (!pending || pending.state !== params.get("state") || Date.now() - pending.createdAt > 10 * 60 * 1000) {
    throw new Error("Состояние входа не совпало или устарело. Повторите вход.");
  }
  if (params.has("error")) throw new Error(`Keycloak: ${params.get("error")}`);
  if (params.has("iss") && params.get("iss") !== config.issuerUri) throw new Error("Неожиданный issuer в ответе входа.");

  const response = await fetch(`${config.issuerUri}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", client_id: config.browserClientId,
      redirect_uri: redirectUri, code: params.get("code"), code_verifier: pending.verifier,
    }),
  });
  if (!response.ok) throw new Error(`Обмен кода на токен завершился с HTTP ${response.status}`);
  const tokens = await response.json();
  accessToken = tokens.access_token;
  idToken = tokens.id_token;
  logoutButton.disabled = false;
  statusElement.textContent = "Вы вошли. Проверка прав происходит на стороне API.";
  await callApi("/api/me");
}

async function callApi(path) {
  const response = await fetch(path, {
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    cache: "no-store",
  });
  const body = await response.text();
  let formatted = body || "(пустой ответ)";
  try { formatted = JSON.stringify(JSON.parse(body), null, 2); } catch { /* Body may be empty. */ }
  resultElement.textContent = `GET ${path}\nHTTP ${response.status}\n\n${formatted}`;
  if (response.status === 401 && accessToken) statusElement.textContent = "Токен отклонён или истёк. Войдите снова.";
}

loginButton.addEventListener("click", () => login().catch(showError));
logoutButton.addEventListener("click", () => {
  const url = new URL(`${config.issuerUri}/protocol/openid-connect/logout`);
  url.search = new URLSearchParams({
    client_id: config.browserClientId, id_token_hint: idToken, post_logout_redirect_uri: redirectUri,
  });
  accessToken = undefined;
  idToken = undefined;
  window.location.assign(url);
});
document.querySelectorAll("[data-path]").forEach(button => {
  button.addEventListener("click", () => callApi(button.dataset.path).catch(showError));
});
function showError(error) { statusElement.textContent = error.message; }

(async () => {
  const response = await fetch("/api/public");
  if (!response.ok) throw new Error("Не удалось загрузить конфигурацию API.");
  config = await response.json();
  loginButton.disabled = false;
  statusElement.textContent = "Вы не вошли.";
  await finishLogin();
})().catch(showError);
