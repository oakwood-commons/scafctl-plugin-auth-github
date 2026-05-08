# scafctl-plugin-auth-github

GitHub authentication handler plugin for scafctl

## Names

This plugin uses the following names across different surfaces:

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-auth-github` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-auth-github` |
| Binary | `scafctl-plugin-auth-github` |
| Provider name | `auth-github` |
| Catalog artifact | `auth-github` |

The **provider name** is what users reference in solutions (`provider: auth-github`).
It comes from the RPC contract (`GetProviders` / `GetProviderDescriptor`), not from
the binary filename.

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

```bash
scafctl auth login github
```

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