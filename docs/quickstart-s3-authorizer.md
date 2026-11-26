# Quickstart: S3 with your own authorization

<!-- description: Run an OpenXet server that keeps its files in an Amazon S3 bucket and its index in Postgres, and asks your own service who may read, write, create and delete; watch it allow and refuse with the stock hf CLI, then read the index as your service would. -->

Run an OpenXet server that keeps its files in an Amazon S3 bucket and
its index in Postgres, and lets your own service decide who may do what.
You connect the server to S3 and to Postgres, start a small
authorization service, connect the server to it, and then try an upload
that your service allows, two actions it refuses, and what happens when
it is down. Last, you read the index from Postgres as your service
can.

Run the blocks in one terminal, in an empty directory. This page doesn't
run in CI, since it needs your AWS account. Already followed the
[S3 quickstart](quickstart-s3.md)? Your server is connected to S3:
skip to [step 4](#4-keep-the-index-in-postgres).

## 1. Install

There is no release yet, so `openxet` is built from source. This needs
[Rust](https://rustup.rs) 1.97 or newer, Python 3.10 or newer, `git`
2.37 or newer, and Postgres 12 or newer running on this machine, with
`createdb` and `psql` on your `PATH`. On macOS,
`brew install postgresql@17 && brew services start postgresql@17` sets
that up. The `hf` command line goes into a virtual environment:

```bash install
cargo install --locked --git https://github.com/stubbi/openxet openxet
python3 -m venv .venv && . .venv/bin/activate
pip install 'huggingface_hub>=2.2.0' 'hf_xet>=1.7.0'
```

## 2. Get AWS credentials

OpenXet signs in to S3 with an access key: an access key ID and its
secret access key. Create one for an IAM user in the
[IAM console](https://console.aws.amazon.com/iam/) (Users, your user,
Security credentials, Create access key). Give the user this policy,
with your bucket's name in place of `my-openxet-bucket`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:CreateBucket"],
      "Resource": "arn:aws:s3:::my-openxet-bucket"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::my-openxet-bucket/*"
    }
  ]
}
```

`s3:CreateBucket` is only needed if OpenXet should create the bucket
for you; leave it out for a bucket you already have.

## 3. Connect OpenXet to S3

Choose the bucket and its region. Bucket names are shared by every AWS
account, so pick one that is yours: lowercase letters, digits and
hyphens, 3 to 63 characters. OpenXet keeps its data under a prefix, here
`openxet`, so the bucket can hold other things too.

```bash
BUCKET=my-openxet-bucket
REGION=eu-west-1
```

Then run `openxet storage setup`. For a new bucket, `--create-bucket`
creates it in `$REGION`; for a bucket you already have, leave it out and
give the bucket's own region:

```bash
openxet storage setup "s3://$BUCKET/openxet" --region "$REGION" --create-bucket
```

It asks for your access key. The secret isn't shown as you type it:

```text
Access key id: AKIAIOSFODNN7EXAMPLE
Secret access key:
Created the bucket of s3://my-openxet-bucket/openxet.
The store honours conditional creates.
The credentials are in /home/me/.config/openxet/s3-credentials (mode 0600), the transfer key in /home/me/.config/openxet/transfer.key.
Wrote the configuration to /home/me/.config/openxet/openxet.toml.
```

It checks that the key reaches the bucket before it writes anything, and
stores the key in a file only you can read, never in the configuration.
The [S3 quickstart](quickstart-s3.md#3-connect-openxet-to-s3) explains
each check, and how to pass the key without a terminal.

## 4. Keep the index in Postgres

The bucket holds the files. The index says which files, repositories and
branches exist, and by default it is a SQLite file next to the server.
Put it in Postgres instead, where every server you add later shares it
and your own services can read it:

```bash
createdb openxet
cat >> ~/.config/openxet/openxet.toml <<'EOF'

[index]
url = "postgres://localhost/openxet"
EOF
```

The URL names no user, so Postgres is asked as your own user, as `psql`
does. The server creates its tables the first time it starts. For a
database that needs a password, keep it out of the URL: put it in a file
only you can read and name the file with `password_file`, or set
`PGPASSWORD` ([`[index]`](reference/config.md#index)).

## 5. Write your authorization service

Before every read, write, create or delete, OpenXet will `POST` your
service a question like this one, with the user's own token in the
`Authorization` header:

```json
{"schema":"openxet.authz.v1","action":"write","resource":"dev/demo","namespace":"dev","name":"demo","path":null,"subject":"dev","claims":{}}
```

Your service answers `true` or `false`. Save this one as `authorize.py`.
It uses only Python's standard library, checks that each question really
comes from your OpenXet server, and prints every decision so you can
watch it work:

```python
import hashlib, hmac, json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET_FILE = os.path.expanduser("~/.config/openxet/authorizer.secret")

def decide(ask, token):
    """Your rules. `token` is the user's bearer token, to look up in your own system."""
    if ask["subject"] != "dev":
        return False
    if ask["action"] == "read":
        return True                          # dev may read every repository
    if ask["action"] in ("write", "create"):
        return ask["namespace"] == "dev"     # but only change its own namespace
    return False                             # and never delete

class Authorize(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        stamp = self.headers.get("X-Openxet-Timestamp", "0")
        try:
            key = open(SECRET_FILE).read().strip().encode()
        except FileNotFoundError:
            key = None  # before `openxet authorizer setup` created it
        mac = key and hmac.new(key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        signed = bool(mac) and hmac.compare_digest(
            self.headers.get("X-Openxet-Signature", ""), "sha256=" + mac)
        fresh = abs(time.time() - int(stamp)) < 300
        ask = json.loads(body)
        allow = signed and fresh and decide(ask, self.headers.get("Authorization"))
        print("allow" if allow else "deny ", ask["action"], ask["resource"], flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"true" if allow else b"false")

    def log_message(self, *args):
        pass  # never log requests: they carry the user's token

HTTPServer(("127.0.0.1", 8000), Authorize).serve_forever()
```

The signature check is what keeps anyone else from asking your service
questions in OpenXet's name: OpenXet signs every question with a secret
that the next step creates, and the service refuses any question that
isn't signed with it or is more than five minutes old.

Start it in the background, with its decisions going to `authorize.log`:

```bash
python3 authorize.py > authorize.log 2>&1 &
AUTH=$!
```

## 6. Connect OpenXet to your service

```bash
openxet authorizer setup http://127.0.0.1:8000/authorize
```

```text
http://127.0.0.1:8000/authorize answered the test request (openxet-setup reading openxet-setup/test): deny.
Created the signing secret in /home/me/.config/openxet/authorizer.secret (mode 0600): check X-Openxet-Signature with it.
Added [authorizer] to /home/me/.config/openxet/openxet.toml.
```

`authorizer setup` first sends your service a signed test question and
needs an answer. Either answer will do: here it is `deny`, because the
secret didn't exist yet when the question arrived. If the service can't
be reached or answers something else, setup stops and writes nothing.

Then it creates the signing secret, readable only by you, and adds this
to the end of the configuration that step 3 wrote, leaving the rest as
it was:

```toml
[authorizer]
url = "http://127.0.0.1:8000/authorize"
secret_file = "/home/me/.config/openxet/authorizer.secret"
```

From now on your service decides everything, including for the dev
token. The URL must be `https://`, or `http://` to this machine as here.
For a service elsewhere, run it behind HTTPS and pass its `https://` URL.

## 7. Start the server

```bash
openxet serve --config ~/.config/openxet/openxet.toml --port 0 --json > serve.json 2> serve.log &
SERVER=$!
until [ -s serve.json ]; do sleep 0.1; done
```

Before it takes any request, the server checks the bucket again with the
stored key, and creates its tables in Postgres. The configuration has no `[auth]` section, so the server runs
in [dev mode](reference/config.md#dev-mode): one token, for the user
`dev`, which `--json` prints with the endpoint once the server is ready.
The token proves who the user is; your service decides what they may do.

## 8. Upload and download: allowed

Point `hf` at the server, make a folder with a README and a 4 MiB file,
and upload it to the repository `dev/demo`:

```bash
export HF_ENDPOINT=$(python3 -c 'import json; print(json.load(open("serve.json"))["endpoint"])')
export HF_TOKEN=$(python3 -c 'import json; print(json.load(open("serve.json"))["token"])')
mkdir demo
echo "# demo" > demo/README.md
head -c 4194304 /dev/urandom > demo/data.bin
hf upload dev/demo demo .
```

```text
Found 2 files to upload
✓ Uploaded
  url: http://127.0.0.1:56398/dev/demo/commit/b9b9017d6ff9ddab5494baec049a73a98c416a34
```

Download it again and compare:

```bash
hf download dev/demo --local-dir downloaded
cmp demo/data.bin downloaded/data.bin
```

`cmp` prints nothing: the bytes came back from S3. Your service was asked
for each step:

```bash
cat authorize.log
```

```text
allow create dev
allow read dev/demo
allow write dev/demo
```

Uploading to a repository that doesn't exist yet creates it, so your
service was asked to `create` in the namespace `dev`, then to `read` and
`write` `dev/demo`. The download asked nothing new: OpenXet reuses an
allow for the same user and token for up to 30 seconds, so a download
doesn't ask once per file.

## 9. Write elsewhere and delete: refused

Your rules let `dev` change only its own namespace, and nobody delete.
Try both:

```bash
hf upload acme/demo demo .
```

```text
403 Forbidden: You don't have the rights to create a model under the namespace "acme".
```

```bash
hf repos delete dev/demo --yes
```

```text
403 Forbidden: You don't have the rights to delete dev/demo.
```

```bash
tail -n 2 authorize.log
```

```text
deny  create acme
deny  delete dev/demo
```

Your service refused, so OpenXet refused, and `dev/demo` is still there.
Deleting a branch or a tag is asked the same way, as
`dev/demo/branch/NAME` or `dev/demo/tag/NAME`.

## 10. Your service is down: refused too

Stop your service, wait out the 30 seconds an allow is reused, and ask
the server for the README:

```bash
kill "$AUTH"
sleep 31
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $HF_TOKEN" \
  "$HF_ENDPOINT/dev/demo/resolve/main/README.md"
```

```text
503
```

When OpenXet can't get an answer, because your service is down, too slow
(more than 2 seconds), redirects or answers something other than `true`
or `false`, it refuses with `503 authorizer_unavailable`. It never lets
a request through without an answer. The server log names your
service's URL and never a token:

```bash
grep authorizer_unavailable serve.log | head -n 1
```

Start your service again, and the next request is answered as before:

```bash
python3 authorize.py >> authorize.log 2>&1 &
AUTH=$!
```

## 11. Look in the bucket

```bash
aws s3 ls "s3://$BUCKET/openxet/" --recursive
```

Or open the bucket in the [S3 console](https://console.aws.amazon.com/s3/).
Under `openxet/` are the file's chunks (`xorbs/`), what the upload
registered (`shards/`, `registrations/`, `xorb-owners/`), the repository's
Git history (`repos/`) and the conditional-create checks (`probe/`). Your
authorization service stores nothing there: it only answers questions.

## 12. Look in the index

Your service can read the index too, to decide by what is in it: who
owns a repository, its labels, whether it is private. Give it a role of
its own that may only read, and only the tables it needs:

```bash
psql openxet -c "CREATE ROLE authorizer LOGIN" -c "GRANT SELECT ON repos, refs, audit_log TO authorizer"
psql -U authorizer openxet -c "SELECT namespace, name, private, labels FROM repos"
```

```text
 namespace | name | private |  labels
-----------+------+---------+-----------
 dev       | demo | f       | ["model"]
(1 row)
```

`dev/demo` is there and `acme/demo` isn't, as your service decided. The
role can't change anything, nor read what you didn't grant:

```bash
psql -U authorizer openxet -c "DELETE FROM repos"
```

```text
ERROR:  permission denied for table repos
```

Your service would run the same queries with a Postgres library, such as
`psycopg` in Python, connecting as `authorizer`. The tables are described
in [reading the index](reference/config.md#reading-the-index-from-your-own-services).
They belong to OpenXet: read them, never write them.

## 13. Stop

```bash
kill "$SERVER" "$AUTH"
```

To run them again, start `authorize.py` first, then
`openxet serve --config ~/.config/openxet/openxet.toml` from this same
directory: the index stays in Postgres and every file in S3, while the
server keeps a Git cache in `openxet-data` here.

When you are done trying, delete the `openxet/` prefix or the bucket in
the S3 console, so it stops costing storage, and drop the database with
`dropdb openxet`.

## Make it yours

- **Your own rules.** Replace `decide`. `ask` has the `action` (`read`,
  `write`, `create` or `delete`), the `resource` and its parts
  (`namespace`, `name`, `path`), and who the user is (`subject`,
  `claims`); `token` is their bearer token, to look up in your own
  system, and you can look the repository up in the index (step 12). The
  [authorizer reference](reference/authorizer.md) lists which request
  asks which action.
- **How long answers are reused.** Add `allow_ttl` and `deny_ttl` to
  `[authorizer]` (30 and 5 seconds by default), or `"0s"` to ask every
  time; your service can also answer `{"allow": true, "ttl_seconds": 5}`.
  A user whose access you take away may keep it for up to `allow_ttl`.
- **Real users.** Dev mode has one user. Give each person their own
  [static token](reference/config.md#static-tokens), or sign them in
  with [OIDC](reference/config.md#oidc) (Auth0, Okta, Entra ID and
  others). Your service then sees their `subject` and `claims`, with no
  change to it.

## If something goes wrong

| Message | What to do |
| ------- | ---------- |
| `storage setup`: `… already sets storage.url` | The configuration is already connected to S3: go on with step 4. |
| `serve`: `could not open the index at postgres://…` | Start Postgres, check that `createdb openxet` ran, and that `psql openxet` connects as you. |
| `authorizer setup`: `could not reach …` | Start `authorize.py` (step 5), check the URL and port, and run setup again. |
| `authorizer setup`: `… already has an [authorizer]` | It is already connected: go on with step 7. To use another URL, remove the `[authorizer]` section and run setup again. |
| `authorizer setup`: `the URL must be https://, or http:// to a loopback address` | Use `https://`, or `http://` to `127.0.0.1`, `::1` or `localhost`. |
| Every request is `403` | Your service answers `false`. Check `authorize.log`: if everything is denied, the signature doesn't match, so check that `SECRET_FILE` is the file `authorizer setup` created and restart `authorize.py`. |
| Every request is `503` | OpenXet gets no answer: check that `authorize.py` is running, and look for `authorizer_unavailable` in `serve.log`. |

The S3 errors of `storage setup` are listed in the
[S3 quickstart](quickstart-s3.md#if-something-goes-wrong), and every
error, with `--json` too, in [exit codes](reference/exit-codes.md).

## Next

- [`[index]`](reference/config.md#index): the Postgres settings, and
  the tables your services can read.
- [Authorizer endpoint](reference/authorizer.md): the question and the
  answer field by field, and how to check the signature.
- [`openxet authorizer setup`](reference/cli.md#openxet-authorizer-setup):
  every option, including `--dry-run` to test a service without writing
  anything.
- [Quickstart: hf and git](quickstart-hub.md): clone and push the same
  repository with `git`, which your service authorizes the same way.
