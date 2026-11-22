# Authorizer endpoint

<!-- description: Let your own service decide who may read, write, create and delete in OpenXet: the request OpenXet sends, the answer it expects, how to check the signature, and a reference endpoint in Python. -->

With an authorizer, your own service decides every action on every
repository. Before OpenXet lets a user read, write, create or delete, it
sends your endpoint a `POST` saying who wants to do what to which
resource, with the user's bearer token, and does what the answer says.

OpenXet still checks the token first: an unknown or expired token is
refused before your endpoint is asked. Today that is the dev token or a
[static token](config.md#static-tokens); with
[OIDC](config.md#oidc) (Auth0, Okta, Entra ID and others) it is your
identity provider's token, with no change to your endpoint.

## Set it up

```bash
openxet authorizer setup https://auth.example.com/openxet/authorize
```

`authorizer setup` sends your endpoint one test request, signed as the
server will sign them, and needs an answer, allow or deny. Then it creates
a signing secret in `~/.config/openxet/authorizer.secret` (mode `0600`)
and adds this section to `~/.config/openxet/openxet.toml`, creating the
file if needed and otherwise leaving the rest of it as it is:

```toml
[authorizer]
url = "https://auth.example.com/openxet/authorize"
secret_file = "/home/me/.config/openxet/authorizer.secret"
```

Restart the server to use it. The URL must be `https://`, or `http://` to
this machine (`127.0.0.1`, `::1` or `localhost`). See
[`openxet authorizer setup`](cli.md#openxet-authorizer-setup) for every
option.

| Key | Default | Bounds | Meaning |
| --- | ------- | ------ | ------- |
| `url` | required | `https://`, or `http://` to a loopback address | Where decisions are asked. |
| `secret_file` | none | a file path, mode `0600` | The key requests are signed with. Without it, requests are unsigned. |
| `timeout` | `2s` | `1s` to `30s` | How long one decision may take. |
| `allow_ttl` | `30s` | `0s` to `1h` | The longest an allow is reused for the same caller. |
| `deny_ttl` | `5s` | `0s` to `1h` | The longest a deny is reused for the same caller. |

With `[authorizer]`, your endpoint decides everything:
[`[[auth.rules]]`](config.md#rules) can't be set beside it, and in
[dev mode](config.md#dev-mode) it replaces the rule that lets the dev
token do everything. The dev token still signs in.

## The request

```http
POST /openxet/authorize HTTP/1.1
Content-Type: application/json
Authorization: Bearer oxt_…
X-Openxet-Timestamp: 1795000000
X-Openxet-Signature: sha256=5f0c…

{"schema":"openxet.authz.v1","action":"write","resource":"acme/model","namespace":"acme","name":"model","path":null,"subject":"dev","claims":{}}
```

| Field | Meaning |
| ----- | ------- |
| `action` | `read`, `write`, `create` or `delete`. |
| `resource` | What the action is on, as a repository's URL names it: `acme/model` for a repository, `acme` for `create` (a repository in that namespace), and `acme/model/branch/dev` or `acme/model/tag/v1` for deleting a branch or a tag. |
| `namespace`, `name`, `path` | `resource`'s parts: `name` is `null` for `create`, `path` is `branch/{name}` or `tag/{name}` for a deleted ref and otherwise `null`. |
| `subject` | Who OpenXet verified the token as, such as `dev`, a static token's `subject`, or `{name}:{sub}` for an [OIDC](config.md#oidc) issuer named `name`. `anonymous` for a request without a token. |
| `claims` | The user's claims, such as `groups`, as lists of strings. |

The `Authorization` header is the user's own token, exactly as they sent
it; it is absent when they sent none. Treat it as the secret it is: never
log it.

Which requests ask which action:

| Action | Asked when a user |
| ------ | ----------------- |
| `read` | downloads, lists, clones or fetches a repository, and before most other actions on it, since a repository they can't read answers as one that doesn't exist |
| `write` | commits or pushes (including removing files), creates a branch or tag, or changes labels |
| `create` | creates a repository in a namespace |
| `delete` | deletes a repository, a branch or a tag |

A download's bytes travel with a token OpenXet hands out after a `read`
was allowed, so your endpoint is asked once per download, not once per
chunk.

## The answer

Answer `200` with one of:

- `true` or `false`;
- `{"allow": true}` or `{"allow": false}`, with an optional
  `"ttl_seconds"` that shortens how long OpenXet reuses the answer.

OpenXet fails closed: a timeout, a status other than `2xx`, a redirect or
any other body refuses the request with `503 authorizer_unavailable`, never
allows it, and is never reused. The log names your URL, the action and the
resource, never a token or the secret.

An allow is reused for up to `allow_ttl` and a deny for up to `deny_ttl`,
per caller: a different user, different claims or a different token is
always asked again.

## Check the signature

With `secret_file`, every request is signed. The key is the file's
contents without the trailing newline. Recompute HMAC-SHA256 over the
timestamp, a dot and the raw body, compare it in constant time with
`X-Openxet-Signature`, and refuse a timestamp more than five minutes off,
so a captured request can't be replayed.

## A reference endpoint

This endpoint, in Python with only the standard library, checks the
signature and lets the dev user read and write everything, refusing
deletes. Replace `decide` with your own rules:

```python
import hashlib, hmac, json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET_FILE = os.path.expanduser("~/.config/openxet/authorizer.secret")

def secret():
    try:
        return open(SECRET_FILE).read().strip().encode()
    except FileNotFoundError:
        return None  # before `openxet authorizer setup` created it

def decide(ask, token):
    return ask["subject"] == "dev" and ask["action"] != "delete"

class Authorize(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        stamp = self.headers.get("X-Openxet-Timestamp", "0")
        key = secret()
        mac = key and hmac.new(key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        signed = bool(mac) and hmac.compare_digest(
            self.headers.get("X-Openxet-Signature", ""), "sha256=" + mac)
        fresh = abs(time.time() - int(stamp)) < 300
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        allow = signed and fresh and decide(json.loads(body), token)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"true" if allow else b"false")

HTTPServer(("127.0.0.1", 8000), Authorize).serve_forever()
```

Run it, set it up and start the server:

```bash
python3 authorize.py &
openxet authorizer setup http://127.0.0.1:8000/authorize
openxet serve --config ~/.config/openxet/openxet.toml
```

The first time, the secret doesn't exist yet when setup's test request
arrives, so the endpoint answers `false`; that is still an answer, and
setup passes. From then on the endpoint reads the secret setup created.
