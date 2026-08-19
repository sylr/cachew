# Cachew

Cachew (pronounced "cashew") is a tiered, protocol-aware, caching HTTP proxy for software engineering infrastructure. It understands higher-level protocols (Git, Docker, Go modules, etc.) and makes smarter caching decisions than a naive HTTP proxy.

## Strategies

### Git

Caches Git repositories with two complementary techniques:

1. **Snapshots** — periodic `.tar.zst` archives that restore 4–5x faster than `git clone`.
2. **Pack caching** — passthrough caching of packs from `git-upload-pack` for incremental pulls.

Redirect Git traffic through cachew:

```ini
[url "https://cachew.example.com/git/github.com/"]
  insteadOf = https://github.com/
```

Restore a repository from a snapshot (with automatic delta bundle to reach HEAD):

```sh
cachew git restore https://github.com/org/repo ./repo
```

```hcl
git {
  snapshot-interval = "1h"
  repack-interval   = "1h"
}
```

### GitHub Releases

Caches public and private GitHub release assets. Private orgs use a token or GitHub App for authentication.

**URL pattern:** `/github-releases/{owner}/{repo}/{tag}/{asset}`

```hcl
github-releases {
  token        = "${GITHUB_TOKEN}"
  private-orgs = ["myorg"]
}
```

### Go Modules

Go module proxy (`GOPROXY`-compatible). Private modules are fetched via git clone.

**URL pattern:** `/gomod/...`

```sh
export GOPROXY=http://cachew.example.com/gomod,direct
```

```hcl
gomod {
  proxy         = "https://proxy.golang.org"
  private-paths = ["github.com/myorg/*"]
}
```

### Hermit

Caches [Hermit](https://cashapp.github.io/hermit/) package downloads. GitHub release URLs are automatically routed through the `github-releases` strategy.

**URL pattern:** `/hermit/{host}/{path...}`

```hcl
hermit {}
```

### Artifactory

Caches artifacts from JFrog Artifactory with host-based or path-based routing.

```hcl
artifactory "example.jfrog.io" {
  target = "https://example.jfrog.io"
}
```

### Host

Generic reverse-proxy caching for arbitrary HTTP hosts, with optional custom headers.

```hcl
host "https://ghcr.io" {
  headers = {
    "Authorization": "Bearer QQ=="
  }
}

host "https://w3.org" {}
```

### HTTP Proxy

Caching proxy for clients that use absolute-form HTTP requests (e.g. Android `sdkmanager --proxy_host`).

```hcl
proxy {}
```

## Cache Backends

Multiple backends can be configured simultaneously — they are automatically combined into a tiered cache. Cache blocks
are ordered from lowest/nearest to highest/authoritative. Reads check each tier in order and backfill lower tiers on a
hit. Writes go to all tiers in parallel. Replica invalidations evict only non-authoritative tiers; the final cache block
is authoritative. Tiered caches use the metadata backend to track authoritative ETags and invalidate stale lower-tier
copies before falling through to the authoritative tier.

### Memory

In-memory LRU cache.

```hcl
memory {
  limit-mb = 1024   # default
  max-ttl  = "1h"   # default
}
```

### Disk

On-disk LRU cache with TTL-based eviction.

```hcl
disk {
  limit-mb = 250000
  max-ttl  = "8h"
}
```

### S3

S3-compatible object storage (AWS S3, MinIO, etc.).

```hcl
s3 {
  bucket   = "my-cache-bucket"
  endpoint = "s3.amazonaws.com"
  region   = "us-east-1"
}
```

## Authorization (OPA)

Cachew uses [Open Policy Agent](https://www.openpolicyagent.org/) for request authorization. The default policy allows all requests from localhost and restricts remote access to non-admin paths (`/api/*`, `/admin/*`).

Policies must be in `package cachew.authz` and define an `allow` rule. If `allow` is true the request proceeds; otherwise it is rejected with 403.

```hcl
opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if startswith(input.remote_addr, "127.0.0.1:")
  EOF
}
```

Do not authenticate on the raw `Authorization` header (`allow if input.headers["authorization"]`):
any value satisfies it, including one an attacker chooses. Use a verified token instead — see
[OIDC Authentication](#oidc-authentication).

Or reference an external file with optional data:

```hcl
opa {
  policy-file = "./policy.rego"
  data-file   = "./opa-data.json"
}
```

**Input fields:** `input.method`, `input.path` (string array), `input.headers`, `input.remote_addr` (includes port — use `startswith` to match by IP), and `input.token` when a verified OIDC bearer token was presented (see [OIDC Authentication](#oidc-authentication)).

When at least one `oidc-issuer` is configured, `authorization` is omitted from `input.headers`, so
a policy cannot accidentally authenticate on an unverified header.

### Testing policies

The `test` field holds a Rego test module that is run against the policy when `cachewd` starts. Any rule prefixed with `test_` is executed; if a test fails, `cachewd` exits.

```hcl
opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if input.method == "POST"
  EOF
  test = <<EOF
    package cachew.authz_test
    import data.cachew.authz

    test_post_allowed if authz.allow with input as {"method": "POST"}
    test_get_denied if not authz.allow with input as {"method": "GET"}
  EOF
}
```

## OIDC Authentication

`cachewd` can verify `Authorization: Bearer <jwt>` tokens against one or more trusted OIDC
issuers, and hand the verified claims to the OPA policy as `input.token`. This is how remote
callers reach `/api/*` and `/admin/*` without widening an IP allow-list or sharing a static
secret.

```hcl
oidc-issuer "https://abc123-def456-ghi789.tokens.sts.global.api.aws" {
  audiences   = ["https://cachew.example.com"]
  # jwks-uri   = "..."               # skip OIDC discovery
  # algorithms = ["RS256", "ES384"]  # only asymmetric algorithms are accepted
  # clock-skew = "30s"
}
```

The issuer label must exactly match the token's `iss` claim. `audiences` is required: it is what
stops a token minted for a different service being replayed at cachew.

Behaviour:

- **No token, a non-`Bearer` scheme, or a Bearer credential for something else** — the request
  passes through unchanged and carries no claims, so existing localhost and path rules apply as
  before. "Something else" means an opaque token or a JWT whose `iss` is not a configured issuer:
  strategies that forward client credentials upstream (artifactory, github-releases) keep
  working. A passed-through credential yields no `input.token`, so policy still denies `/api`
  and `/admin`.
- **A `Bearer` JWT naming a configured issuer that fails verification** — rejected with `401`
  before policy runs. That covers a bad signature, an expired or not-yet-valid token, a missing
  expiry, a disallowed algorithm, a missing `kid`, and a mismatched audience.
- **A verified token** — `input.token` is populated and policy decides.

`cachewd` starts even if an issuer is temporarily unreachable; until its keys can be fetched,
every bearer token is rejected with `401`. Invalid *configuration*, by contrast, is fatal at
startup.

Issuers must be configured in the config file. Unlike other settings, they cannot be supplied via
`CACHEW_*` environment variables, because the issuer URL is a block label.

### Writing policy against claims

```
input.token = {
  "issuer":   "https://abc123-def456.tokens.sts.global.api.aws",
  "subject":  "arn:aws:iam::123456789012:role/cachew-admin",
  "audience": ["https://cachew.example.com"],
  "claims":   { ... every claim in the token ... }
}
```

For AWS STS, `sub` is the **ARN of the IAM principal** that requested the token, and all
AWS-specific claims are nested under a single claim named `https://sts.amazonaws.com/` —
`aws_account`, `source_region`, `org_id`, `principal_tags`, `request_tags`, plus session context
such as `ec2_source_instance_arn`. That key contains slashes, so Rego must use bracket notation.

```hcl
opa {
  policy = <<EOF
    package cachew.authz

    default allow := false

    # Unauthenticated: loopback is trusted, and the strategy paths stay public.
    allow if startswith(input.remote_addr, "127.0.0.1:")
    allow if not input.path[0] in {"api", "admin"}

    aws := input.token.claims["https://sts.amazonaws.com/"]

    # Profiling endpoints are never reachable over the network, token or not.
    # Note this is a predicate the allow rules exclude, not a competing
    # `allow := false` rule, which would be an eval_conflict_error.
    is_pprof if {
      input.path[0] == "admin"
      input.path[1] == "pprof"
    }

    allow if {
      input.path[0] == "api"
      input.token.subject in {
        "arn:aws:iam::123456789012:role/cachew-ci",
        "arn:aws:iam::123456789012:role/cachew-admin",
      }
    }

    allow if {
      input.path[0] == "admin"
      not is_pprof
      aws.aws_account == "123456789012"
      aws.principal_tags.team == "platform"
    }
  EOF
}
```

`input.token` is absent for unauthenticated requests, so every rule above becomes *undefined*
rather than false and `default allow := false` wins. The policy is fail-closed by construction.

### Finding your AWS issuer URL

The issuer is account-specific, so read it from a real token rather than guessing:

```sh
aws sts get-web-identity-token \
  --audience https://cachew.example.com \
  --signing-algorithm RS256 \
  --region eu-west-1 \
  --query WebIdentityToken --output text
```

Decode the payload to see `iss`, `sub` and the nested claims. Note that this API is not available
on the global STS endpoint, and the account must have outbound web identity federation enabled —
otherwise it returns `OutboundWebIdentityFederationDisabled`.

## Client Configuration

The `cachew` client reads an optional HCL configuration file holding named **contexts**, each
describing a server and how to authenticate to it. Resolution order:
`--config`, `$CACHEW_CONFIG`, `$XDG_CONFIG_HOME/cachew/config.hcl`,
`~/.config/cachew/config.hcl`. A missing file is fine — cachew works with no configuration.

```hcl
default-context = "prod"

context "prod" {
  url         = "https://cachew.example.com"
  description = "prod via OIDC"
  oidc {
    audience             = ["https://cachew.example.com"]
    signing-algorithm    = "RS256"     # RS256 or ES384
    duration             = "15m"       # 60s to 1h
    cache                = true
    cache-refresh-before = "2m"
    aws-sts {
      region  = "eu-west-1"
      profile = "my-profile"
      # tags = { "team": "platform" }  # become request_tags claims
      # assume-role {
      #   role-arn     = "arn:aws:iam::111111111111:role/cachew-oidc"
      #   session-name = "cachew-cli"
      # }
    }
  }
}

context "local" {
  url = "http://127.0.0.1:8080"
}
```

Select a context with `--context` (`CACHEW_CONTEXT`). With no context named, `default-context` is
used; failing that, a lone context is taken as implicit.

**Token sources** — exactly one per `oidc` block:

- `aws-sts` — calls `sts:GetWebIdentityToken`, so an existing AWS identity becomes the cachew
  identity with no new credential to distribute. `region` is required.
- `exec` — runs a command and reads the token from stdout, for any other issuer:
  ```hcl
  exec {
    command = ["aws", "sts", "get-web-identity-token",
               "--audience", "https://cachew.example.com",
               "--signing-algorithm", "RS256",
               "--query", "WebIdentityToken", "--output", "text"]
  }
  ```
- `static` — one of `token`, `token-file` or `token-env`, for a token the platform already
  provides (a Kubernetes projected service-account token, a GitHub Actions ID token). It is never
  cached: `token-file` and `token-env` are re-read on every request so in-place rotation is
  picked up immediately.

With `cache = true`, `aws-sts` and `exec` tokens are stored at
`<user cache dir>/cachew/tokens/<context>-<config hash>.jwt` with `0600` permissions and reused
until `cache-refresh-before` ahead of expiry, so a script calling `cachew` in a loop does not
mint one per invocation. The filename embeds a hash of the context's `oidc` settings and, for `aws-sts`, the ambient
identity selectors (`AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_ROLE_ARN`,
`AWS_WEB_IDENTITY_TOKEN_FILE`), so editing the context or switching profile invalidates the
entry instead of replaying a token minted for the previous identity. Raw exported credentials
(`AWS_ACCESS_KEY_ID` etc.) are not tracked — they rotate for the same identity — so when
switching identities that way, use distinct profiles or `cache = false`.
A cache entry is ignored unless it is a regular file with owner-only permissions, and
`cache-refresh-before` must be shorter than `duration`. These are bearer credentials: anyone
holding one can use it until it expires, so keep `duration` short and prefer `cache = false` on
shared machines.

`--authorization` still works and takes precedence over a context's OIDC source.

## GitHub App Authentication

For private Git repositories and GitHub release assets, configure a GitHub App:

```hcl
github-app {
  app-id           = "12345"
  private-key-path = "./github-app.pem"
  installations    = { "myorg": "67890" }
}
```

Installations can also be discovered dynamically via the GitHub API.

## CLI

### Server (`cachewd`)

```sh
cachewd --config cachew.hcl
cachewd --schema  # print config schema
```

### Client (`cachew`)

```sh
# Object operations
cachew get <namespace> <key> [-o file]
cachew put <namespace> <key> [file] [--ttl 1h]
cachew stat <namespace> <key>
cachew delete <namespace> <key>
cachew namespaces

# Directory snapshots
cachew save <namespace> <directory> [paths...] (--key <key> | -H <glob>) [--ttl 1h] [--exclude pattern]
cachew restore <namespace> <directory> (--key <key> | -H <glob>)  # exit 0 hit, 2 miss, 1 error

# Git
cachew git restore <repo-url> <directory> [--no-bundle]
```

**Global flags:** `--url` (`CACHEW_URL`), `--config` (`CACHEW_CONFIG`), `--context` (`CACHEW_CONTEXT`), `--authorization` (`CACHEW_AUTHORIZATION`), `--platform` (prefix keys with `os-arch`), `--daily`/`--hourly` (prefix keys with date).

`--url` wins over `CACHEW_URL`, which wins over the selected context's `url`, which wins over the
`http://127.0.0.1:8080` default. See [Client Configuration](#client-configuration).

## Observability

```hcl
log {
  level = "info"  # debug, info, warn, error
}

metrics {
  service-name = "cachew"
}
```

Admin endpoints: `/_liveness`, `/_readiness`, `PUT /admin/log/level`, `/admin/pprof/`.

## Full Configuration Example

```hcl
state = "./state"
bind  = "0.0.0.0:8080"
url   = "http://cachew.example.com:8080/"

log {
  level = "info"
}

opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if startswith(input.remote_addr, "127.0.0.1:")
  EOF
}

metrics {}

github-app {
  app-id           = "12345"
  private-key-path = "./github-app.pem"
}

git-clone {}

git {
  snapshot-interval = "1h"
  repack-interval   = "1h"
}

github-releases {
  token        = "${GITHUB_TOKEN}"
  private-orgs = ["myorg"]
}

gomod {
  proxy         = "https://proxy.golang.org"
  private-paths = ["github.com/myorg/*"]
}

hermit {}

host "https://ghcr.io" {
  headers = {
    "Authorization": "Bearer ${GHCR_TOKEN}"
  }
}

disk {
  limit-mb = 250000
  max-ttl  = "8h"
}

proxy {}
```
