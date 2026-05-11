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

### UserCertificateProvider

| Property | Default | Description |
| --- | --- | --- |
| athenz.zts.user_cert.idp_config_endpoint | | OIDC discovery endpoint for the IdP |
| athenz.zts.user_cert.idp_token_endpoint | | OIDC token endpoint for the IdP |
| athenz.zts.user_cert.idp_jwks_endpoint | | OIDC JWKS endpoint for the IdP |
| athenz.zts.user_cert.idp_client_id | | Client ID for the IdP |
| athenz.zts.user_cert.idp_client_secret | | Client secret for the IdP (if not using PKCE) |
| athenz.zts.user_cert.idp_audience | | Expected audience for the ID token |
| athenz.zts.user_cert.idp_redirect_uri | http://localhost:9213/oauth2/callback | Redirect URI for the IdP |
| athenz.zts.user_cert.user_name_claim | sub | Claim name for the user name |
| athenz.zts.user_cert.connect_timeout | 5000 | Connection timeout in milliseconds |
| athenz.zts.user_cert.read_timeout | 5000 | Read timeout in milliseconds |

