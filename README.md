# athenz-auth-core

This is an unofficial repository to provide tools, packages and instructions for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

## How to build

```
VERSION=0.0.0
ATHENZ_PACKAGE_VERSION="$(curl -s https://api.github.com/repos/AthenZ/athenz/tags | jq -r .[].name | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g' | sort -ru | head -n1)"
docker build --build-arg VERSION=${VERSION:-0.0.0} --build-arg ATHENZ_VERSION=${ATHENZ_PACKAGE_VERSION} -t athenz-auth-core .
```

## How to generate pom.xml

```
VERSION=0.0.0
ATHENZ_VERSION="$(curl -s https://api.github.com/repos/AthenZ/athenz/tags | jq -r .[].name | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g' | sort -ru | head -n1)"
JAVA_VERSION=11
cat pom.xml.template \
      | $HOME/.local/bin/yq -p xml -o xml ".project.version=\"${VERSION}\"" \
      | $HOME/.local/bin/yq -p xml -o xml ".project.properties.\"athenz.version\"=\"${ATHENZ_VERSION}\"" \
      | $HOME/.local/bin/yq -p xml -o xml ".project.properties.\"java.version\"=\"${JAVA_VERSION}\"" \
      | tee pom.xml
```

## List of Distributions

### Docker(OCI) Image

[athenz-auth-core](https://github.com/users/ctyano/packages/container/package/athenz-auth-core)

### JAR class package

https://github.com/ctyano/athenz-auth-core/releases

