# Docker image with only `ic-rosetta-api`

There's an image which only builds & ships `ic-rosetta-api`, which is intended
to test against a public test net:

```shell
$ docker build \
    --file ic-rosetta-api.Dockerfile \
    --build-arg GITHUB_TOKEN=token \
    --build-arg RELEASE=master \
    --tag my-ic-rosetta-api \
    .
$ docker run -it --rm --publish 2053:8080 my-ic-testnet --canister-id xxx --ic-url xxx
```
