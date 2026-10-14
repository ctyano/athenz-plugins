# athenz-plugins

This is an unofficial repository to provide tools, packages and instructions for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

## How to build

```
VERSION=0.0.0
ATHENZ_PACKAGE_VERSION="$(curl -s https://api.github.com/repos/AthenZ/athenz/tags | jq -r .[].name | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g' | sort -ru | head -n1)"
docker build --build-arg VERSION=${VERSION:-0.0.0} --build-arg ATHENZ_VERSION=${ATHENZ_PACKAGE_VERSION} -t athenz-plugins .
```

## How to generate pom.xml

```
VERSION=0.0.0
ATHENZ_VERSION="$(curl -s https://api.github.com/repos/AthenZ/athenz/tags | jq -r .[].name | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g' | sort -ru | head -n1)"
JAVA_VERSION=17
cat template/pom.xml \
      | $HOME/.local/bin/yq -p xml -o xml ".project.version=\"${VERSION}\"" \
      | $HOME/.local/bin/yq -p xml -o xml ".project.properties.\"athenz.version\"=\"${ATHENZ_VERSION}\"" \
      | $HOME/.local/bin/yq -p xml -o xml ".project.properties.\"java.version\"=\"${JAVA_VERSION}\"" \
      | tee pom.xml
```

## List of Distributions

### Docker(OCI) Image

[athenz-plugins](https://github.com/users/ctyano/packages/container/package/athenz-plugins)

### JAR class package

https://github.com/ctyano/athenz-plugins/releases

## Configuration

### OIDCJwtAuthority

| Property | Default | Description |
| --- | --- | --- |
| athenz.auth.principal.auth.oidc.jwt | Authorization | HTTP Header name for the OIDC JWT |
| athenz.auth.principal.auth.oidc.jwt.domain | user | Athenz domain for the principal |
| athenz.auth.principal.auth.oidc.jwt.issuer | https://athenz-zts-server.athenz:4443/zts/v1 | Expected issuer for the JWT |
| athenz.auth.principal.auth.oidc.jwt.audience | athenz | Expected audience for the JWT |
| athenz.auth.principal.auth.oidc.jwt.jwks_uri | (derived from issuer) | JWKS URI for the issuer |
| athenz.auth.principal.auth.oidc.jwt.claim | sub | Claim name for the principal name |
| athenz.auth.principal.auth.oidc.jwt.boot_time_offset | 300 | Boot time offset in seconds |

### EmailClaimExternalMemberValidator

Set the domain system meta `externalmembervalidator` to `com.yahoo.athenz.auth.impl.EmailClaimExternalMemberValidator` for the external member domain.

When JWT `email` claim values are registered as Athenz role members, configure `OIDCJwtAuthority` with `athenz.auth.principal.auth.oidc.jwt.claim=email`. This validator then checks that the external member name is a valid email address and that its email domain is explicitly allowed.

| Property | Default | Description |
| --- | --- | --- |
| athenz.auth.external_member.email.allowed_domains | | Comma-separated default allowlist of email domains. Use exact domains such as `example.com`; `*.example.com` allows subdomains only. |
| athenz.auth.external_member.email.allowed_domains.\<athenz-domain\> | | Domain-specific allowlist. When set, it overrides the default allowlist for that Athenz domain. |

### EmailTokenExchangeIdentityProvider

Configure ZTS OAuth provider entries with `com.yahoo.athenz.auth.impl.EmailTokenExchangeIdentityProvider` to map an external token email claim to an Athenz external principal.

By default, the `email` claim value `athenz_user@example.com` maps to `email:ext.athenz_user@example.com`. Set `athenz.auth.token_exchange.email.domain` to use a different external member domain, such as `keycloak:ext.athenz_user@example.com`. Set `athenz.auth.token_exchange.email.claim` to read the email address from a different token claim.

| Property | Default | Description |
| --- | --- | --- |
| athenz.auth.token_exchange.email.claim | email | Token claim name used as the email address source. |
| athenz.auth.token_exchange.email.domain | email | Athenz external member domain prefix used when converting the configured email claim value to `<domain>:ext.<email>`. |

### UserCertificateProvider

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.user_cert.idp_config_endpoint | | OIDC discovery endpoint for the IdP |
| athenz.zts.user_cert.idp_jwks_endpoint | | OIDC JWKS endpoint for the IdP |
| athenz.zts.user_cert.idp_audience | | Expected audience for the JWT access token |
| athenz.zts.user_cert.user_name_claim | sub | Claim name for the user name |
| athenz.zts.user_cert.token_expiry_minutes | 15 | Maximum allowed age of the attestation JWT in minutes, evaluated from the `iat` claim |
| athenz.zts.user_cert.connect_timeout | 5000 | Connection timeout in milliseconds |
| athenz.zts.user_cert.read_timeout | 5000 | Read timeout in milliseconds |

The UserCertificateProvider expects the attestation data to contain the JWT access token issued by the IdP. It validates the token signature with the configured JWKS, checks the expected audience, rejects tokens older than the configured number of minutes based on the `iat` claim, and compares the configured user name claim with the requested Athenz principal.

### ExternalMemberCertificateProvider

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.external_member_cert.idp_config_endpoint | | OIDC discovery endpoint for the IdP |
| athenz.zts.external_member_cert.idp_jwks_endpoint | | OIDC JWKS endpoint for the IdP |
| athenz.zts.external_member_cert.idp_audience | | Expected audience for the JWT access token |
| athenz.zts.external_member_cert.member_name_claim | email | Claim name for the external member name |
| athenz.zts.external_member_cert.member_domain | email | Athenz external member domain prefix used when converting the configured claim value to `<domain>:ext.<value>` |
| athenz.zts.external_member_cert.token_expiry_minutes | 15 | Maximum allowed age of the attestation JWT in minutes, evaluated from the `iat` claim |
| athenz.zts.external_member_cert.connect_timeout | 5000 | Connection timeout in milliseconds |
| athenz.zts.external_member_cert.read_timeout | 5000 | Read timeout in milliseconds |

The ExternalMemberCertificateProvider expects the attestation data to contain the JWT access token issued by the IdP. It validates the token signature with the configured JWKS, checks the expected audience, rejects tokens older than the configured number of minutes based on the `iat` claim, and compares the configured member name claim with the requested Athenz external member principal (e.g., `email:ext.user@example.com`).

### VaultCertSigner / VaultCertSignerFactory

`VaultCertSignerFactory` creates a `VaultCertSigner` that requests certificate issuance from [Hashicorp Vault PKI Secret Engine](https://developer.hashicorp.com/vault/docs/secrets/pki).

The signer authenticates to Vault via **AppRole** (`POST /v1/auth/{mount}/login` with `role_id` and `secret_id`) and dynamically obtains a client token. The token is cached and automatically refreshed on 401 responses.

Configure ZTS to use this factory class:

```
athenz.zts.cert_signer_factory_class=com.yahoo.athenz.common.server.cert.impl.vault.VaultCertSignerFactory
```

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.vault.base_uri | | Vault server URL (required). Example: `https://vault.example.com:8200` |
| athenz.zts.vault.approle_role_id | | AppRole Role ID (required) |
| athenz.zts.vault.approle_secret_id | | AppRole Secret ID (required) |
| athenz.zts.vault.approle_mount_path | approle | AppRole authentication mount path |
| athenz.zts.vault.pki_path | pki | PKI secret engine mount path |
| athenz.zts.vault.role_name | athenz | PKI role name for certificate signing |
| athenz.zts.vault.connect_timeout | 10 | Connection timeout in seconds |
| athenz.zts.certsign_max_expiry_time | 43200 | Maximum certificate expiry time in minutes (default 30 days) |

### InstanceLocalWorkloadProvider

`InstanceLocalWorkloadProvider` accepts an OAuth/OIDC ID token as instance attestation data. It validates the JWT signature, issuer, audience, and standard time claims. If the configured user name claim is present, the requested service must be under that user's home domain. If the user name claim is absent, the issuer must map to an external-member Athenz domain, and the requested service must be under that domain.

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.local_workload.issuer | | Comma-separated allowed issuer list. For a single issuer, this can be used with `athenz.zts.local_workload.jwks_uri` and `athenz.zts.local_workload.external_domain`. |
| athenz.zts.local_workload.jwks_uri | | JWKS URI for the single configured issuer. If unset, the provider tries OIDC discovery and then `<issuer>/.well-known/jwks`. |
| athenz.zts.local_workload.jwks_uri_map | | Semicolon-separated issuer to JWKS URI map. Example: `https://dex.example=jwks-uri;https://okta.example=jwks-uri`. |
| athenz.zts.local_workload.audience | | Comma-separated accepted JWT audiences. |
| athenz.zts.local_workload.user_name_claim | athenz_user | JWT claim containing the Athenz user name. `user.<name>` values are normalized to `<name>`. |
| athenz.zts.local_workload.user_domain_template | home.%s | Root domain template for user-owned services. `%s` is required and is replaced with the normalized user name. Use values such as `home.%s.local` for child domains. |
| athenz.zts.local_workload.external_domain | | External-member Athenz root domain for the single configured issuer. |
| athenz.zts.local_workload.external_domain_map | | Semicolon-separated issuer to external-member root domain map. Example: `https://dex.example=external.dex;https://okta.example=external.okta`. |
| athenz.zts.local_workload.boot_time_offset | 0 | Optional issue-time freshness window in seconds. `0` disables the `iat` freshness check. |

### InstanceLocalAgentProvider

`InstanceLocalAgentProvider` accepts an OAuth/OIDC ID token as Copper Argos attestation data for Local Agent service certificates. It validates the token signature, issuer, audience, and time claims. The provider allows issuance when either the verified token user maps to the requested service domain's home-domain owner, or a verified external member name from the token belongs to the requested domain's `admin` role.

The provider resolves signing keys by OIDC Discovery from the token `iss` claim first. If the issuer's `.well-known/openid-configuration` cannot provide `jwks_uri`, it falls back to the configured JWKS endpoint.

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.local_agent.issuer | | Optional comma-separated issuer allowlist. If unset, any issuer is accepted when its token can be verified. |
| athenz.zts.local_agent.jwks_uri | | Fallback JWKS URI used when OIDC Discovery does not resolve a key endpoint. |
| athenz.zts.local_agent.jwks_uri_map | | Semicolon-separated issuer to fallback JWKS URI map. Example: `https://dex.example=jwks-uri;https://okta.example=jwks-uri`. |
| athenz.zts.local_agent.audience | | Required comma-separated accepted JWT audiences. |
| athenz.zts.local_agent.user_name_claim | | Optional single JWT claim for the Athenz home-domain user name. Overrides `user_name_claims` when set. |
| athenz.zts.local_agent.user_name_claims | athenz_user,preferred_username,name,sub | Ordered JWT claims checked for the Athenz home-domain user name. `user.<name>` values are normalized to `<name>`. |
| athenz.zts.local_agent.user_domain_template | home.%s | Root domain template for user-owned services. `%s` is replaced with the normalized user name. |
| athenz.zts.local_agent.external_member_claims | external_members,email,preferred_username,sub | JWT claims used as external member names for target-domain `admin` role checks. String and string-list claims are supported. |
| athenz.zts.local_agent.external_member_template | %s | Optional template for external member names, for example `email:ext.%s`. The raw value is also checked. |
| athenz.zts.local_agent.external_identity_provider_class | | Optional `TokenExchangeIdentityProvider` implementation used to map the verified ID token to an Athenz external member name before the `admin` role check. |
| athenz.zts.local_agent.boot_time_offset | 0 | Optional issue-time freshness window in seconds. `0` disables the `iat` freshness check. |
