# scafctl-plugin-auth-github

GitHub authentication handler plugin for scafctl

## Names

This plugin uses the following names across different surfaces:

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-auth-github` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-auth-github` |
| Binary | `scafctl-plugin-auth-github` |
| Auth handler name | `github` |
| Catalog artifact | `auth-github` |

The **auth handler name** is what users reference in CLI commands and solutions (`auth: github`).
It comes from the RPC contract (`GetAuthHandlers`), not from the binary filename.

## Installation

```bash
# Build from source
task build

# Or download from releases
gh release download --repo github.com/oakwood-commons/scafctl-plugin-auth-github
```

## Usage

Register this plugin in your scafctl configuration, then use
the **github** auth handler:

~~~bash
# Interactive login (authorization code + PKCE when clientSecret is configured,
# or device code with automatic browser launch otherwise)
scafctl auth login github

# Open a specific browser (or set $BROWSER as a fallback)
scafctl auth login github --flow interactive --browser msedge

# Pin the localhost OAuth callback port for SSH or devcontainer port forwarding
scafctl auth login github --flow interactive --callback-port 8400

# Authenticate against a GitHub Enterprise Server (GHES) instance
scafctl auth login github --hostname github.example.com

# Sign in to isolated named profiles (e.g., github.com and GHES side-by-side)
scafctl auth login github --profile personal
scafctl auth login github --profile enterprise
scafctl auth status github --profile enterprise
~~~

### Configuration and Profiles

Keys under `auth.github` (or per-profile under `auth.github.profiles.<name>`):

| Key | Default | Notes |
| --- | --- | --- |
| `clientId` | Built-in scafctl OAuth App ID | GitHub OAuth App or GitHub App client ID |
| `clientSecret` | *(unset)* | Enables authorization code + PKCE interactive callback flow |
| `hostname` | `github.com` | GitHub hostname (`github.com` or GHES hostname such as `github.example.com`) |
| `defaultScopes` | *(unset)* | OAuth scopes requested at login when `--scope` is omitted |
| `appId` | *(unset)* | GitHub App numeric ID (or `GITHUB_APP_ID`) |
| `installationId` | *(unset)* | GitHub App installation ID (or `GITHUB_APP_INSTALLATION_ID`) |
| `privateKey` / `privateKeyPath` / `privateKeySecretName` | *(unset)* | GitHub App PEM private key source |
| `httpClient` | 30s timeout, 3 retries, cache off | Optional `httpc` client settings isolated per effective configuration |

Environment variables:

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` / `GH_TOKEN` | Personal access token (`GITHUB_TOKEN` takes precedence) |
| `GITHUB_APP_ID` / `GITHUB_APP_INSTALLATION_ID` | GitHub App identifiers for `github_app` flow |
| `GITHUB_APP_PRIVATE_KEY` / `GITHUB_APP_PRIVATE_KEY_PATH` | GitHub App PEM private key or file path |
| `BROWSER` | Preferred browser executable or fallback list when `--browser` is not passed; falls back to the OS default browser with a warning if unavailable |

### Interactive Callback Pages

During the authorization code + PKCE interactive flow (`clientSecret` configured), the loopback callback server renders branded HTML pages supplied by the host via `ProviderConfig.AuthCallbackPages` (falling back to the built-in `oauth-helpers` pages when unset, and enforcing `MaxAuthCallbackPageBytes`). Callback completion is deferred until authorization code exchange and credential storage finish so post-callback failures render `503 Service Unavailable` with the failure page instead of a false-positive success page.

Once authenticated, reference it in HTTP requests:

```yaml
resolvers:
  data:
    resolve:
      with:
        - provider: http
          inputs:
            url: https://api.example.com/data
            auth: github
```

## Development

```bash
# Run tests
task test

# Run linter
task lint

# Build
task build

# Full CI pipeline (lint + test + build)
task ci
```



## Release

### Publishing to a catalog

A tagged release should publish both the provider artifact and refresh the
catalog index:

```bash
# Publish the provider artifact
scafctl catalog push auth-github --version v1.0.0

# Refresh the catalog index so the provider is discoverable
scafctl catalog index push --catalog oci://ghcr.io/<REGISTRY_OWNER>
```

Both steps are required. Publishing the artifact alone does not make the
provider appear in catalog listings.

### CI release workflow

The release workflow needs two kinds of authentication:

1. **Container registry auth** for OCI push operations (`docker login` or equivalent).
2. **scafctl auth** for catalog operations (`scafctl auth login github --flow pat --registry ghcr.io --write-registry-auth`).

Standard `docker login` is not sufficient for `scafctl catalog index push`.

### Required secrets

| Secret | Scopes | Purpose |
|--------|--------|---------|
| `GITHUB_TOKEN` | Default | Build, test, create release |
| `CATALOG_PUSH_TOKEN` | `repo`, `read:packages`, `write:packages` | Publish artifact and refresh catalog index |

Create the publishing secret at the org or repo level:

```bash
gh secret set CATALOG_PUSH_TOKEN --org <ORG> --repos scafctl-plugin-auth-github --body "$TOKEN"
```

### Token strategy

For official providers, use a machine account or GitHub App for the publishing
token rather than a personal account. This avoids tying release capability to
an individual developer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.