# InstanceLocalAgentProvider vs InstanceLocalWorkloadProvider

This document summarizes the functional and behavioral differences between
`InstanceLocalWorkloadProvider` and `InstanceLocalAgentProvider`.

## Summary

`InstanceLocalWorkloadProvider` is an issuer/domain-mapping provider. It accepts an
OAuth/OIDC ID token as attestation data, validates the token, resolves an allowed
root domain from either the authenticated user name or the configured issuer
mapping, and allows service certificate issuance only under that root domain.

`InstanceLocalAgentProvider` is a user/admin-delegation provider for the Local
Agent use case. It accepts an OAuth/OIDC ID token as Copper Argos attestation
data, validates the token, and allows service certificate issuance when either
the token user owns the requested home domain or an external member name derived
from the token belongs to the requested domain's `admin` role.

## Feature Comparison

| Area | InstanceLocalWorkloadProvider | InstanceLocalAgentProvider |
| --- | --- | --- |
| Primary use case | Local workload service certificate issuance | Local Agent service certificate issuance through Copper Argos |
| Attestation data | OAuth/OIDC ID token | OAuth/OIDC ID token |
| Issuer handling | Issuer must be configured directly or through issuer maps | Issuer allowlist is optional; when unset, any issuer is accepted if the token can be verified |
| JWKS resolution order | Configured JWKS first, then OIDC Discovery, then `<issuer>/.well-known/jwks` | OIDC Discovery first, then issuer-specific fallback JWKS, then global fallback JWKS |
| Audience validation | Required | Required |
| Expiration validation | Requires `exp`; JWT processor also validates standard time claims | Requires `exp`, explicitly rejects expired tokens, validates `nbf`, and supports optional `iat` freshness |
| User home-domain authorization | Uses the configured user-name claim to allow services under `home.%s` or another configured template | Uses ordered user-name claims to allow services under `home.%s` or another configured template |
| External IdP authorization | If no user-name claim is present, the issuer can map to an external root domain | Token-derived external member names are checked against the requested domain's `admin` role |
| Athenz role lookup | Not used | Uses `RolesProvider` to check target-domain `admin` membership |
| External identity provider mapping | Not supported | Supports an optional `TokenExchangeIdentityProvider` implementation for member-name mapping |
| Certificate refresh | Rejected | Rejected |
| Returned certificate attributes | `certRefresh=false`, `certUsage=client` | `certRefresh=false`, `certUsage=client` |

## Authorization Model

### InstanceLocalWorkloadProvider

`InstanceLocalWorkloadProvider` resolves one allowed root domain for the token.
The root domain is determined as follows:

1. If the configured user-name claim is present, the provider normalizes the user
   name and applies the configured user-domain template, such as `home.%s`.
2. If the user-name claim is absent, the provider looks up the token issuer in
   the configured external-domain mapping.

The requested service domain must be equal to the resolved root domain or be a
child domain under it. No Athenz role membership is checked.

### InstanceLocalAgentProvider

`InstanceLocalAgentProvider` authorizes a request through either of two paths:

1. Home-domain ownership: a verified user name from the ID token maps to the
   requested domain through the configured user-domain template.
2. Domain administration: an external member name derived from the verified ID
   token belongs to the requested domain's `admin` role.

The second path lets a domain administrator authorize certificate issuance for a
Local Agent service by adding the corresponding external member to the target
domain's `admin` role.

## JWKS Resolution

`InstanceLocalWorkloadProvider` keeps backward-compatible behavior by preferring
configured JWKS endpoints before attempting OIDC Discovery.

`InstanceLocalAgentProvider` follows the Local Agent requirement more directly:
it first attempts OIDC Discovery from the token `iss` claim by querying:

```text
<issuer>/.well-known/openid-configuration
```

If Discovery returns a `jwks_uri`, that endpoint is used. If Discovery fails or
does not provide `jwks_uri`, the provider falls back to:

1. `athenz.zts.local_agent.jwks_uri_map` for the token issuer.
2. `athenz.zts.local_agent.jwks_uri` as the global fallback.

## Configuration Differences

### InstanceLocalWorkloadProvider

Relevant properties:

| Property | Purpose |
| --- | --- |
| `athenz.zts.local_workload.issuer` | Allowed issuers |
| `athenz.zts.local_workload.jwks_uri` | Single-issuer JWKS endpoint |
| `athenz.zts.local_workload.jwks_uri_map` | Issuer-to-JWKS fallback map |
| `athenz.zts.local_workload.audience` | Accepted token audiences |
| `athenz.zts.local_workload.user_name_claim` | User-name claim |
| `athenz.zts.local_workload.user_domain_template` | User root-domain template |
| `athenz.zts.local_workload.external_domain` | Single-issuer external root domain |
| `athenz.zts.local_workload.external_domain_map` | Issuer-to-external-domain map |
| `athenz.zts.local_workload.boot_time_offset` | Optional `iat` freshness window |

### InstanceLocalAgentProvider

Relevant properties:

| Property | Purpose |
| --- | --- |
| `athenz.zts.local_agent.issuer` | Optional issuer allowlist |
| `athenz.zts.local_agent.jwks_uri` | Global fallback JWKS endpoint |
| `athenz.zts.local_agent.jwks_uri_map` | Issuer-to-fallback-JWKS map |
| `athenz.zts.local_agent.audience` | Accepted token audiences |
| `athenz.zts.local_agent.user_name_claim` | Single user-name claim override |
| `athenz.zts.local_agent.user_name_claims` | Ordered user-name claim list |
| `athenz.zts.local_agent.user_domain_template` | User root-domain template |
| `athenz.zts.local_agent.external_member_claims` | Claims used as external member names |
| `athenz.zts.local_agent.external_member_template` | Optional member-name formatting template |
| `athenz.zts.local_agent.external_identity_provider_class` | Optional `TokenExchangeIdentityProvider` mapper |
| `athenz.zts.local_agent.boot_time_offset` | Optional `iat` freshness window |

## Operational Guidance

For `InstanceLocalAgentProvider`, configure `athenz.zts.local_agent.issuer` in
production unless accepting any discoverable/verifiable issuer is intentional.
Leaving the issuer allowlist unset is useful for development and multi-IdP
experiments, but a production deployment should normally restrict trusted
issuers explicitly.

Use `athenz.zts.local_agent.external_identity_provider_class` when token claims
need to be converted into Athenz external member names through existing token
exchange identity mapping logic, such as mapping an email claim to
`email:ext.<address>`.
