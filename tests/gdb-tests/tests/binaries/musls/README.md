# musl libraries used by tests

|     name     | version |         pkgversion         |       docker tag/id       |                              sha256                              |
| ------------ | ------- | -------------------------- | ------------------------- | ---------------------------------------------------------------- |
| ld-musl-124.x86_64.so.1 | 1.2.4 | musl-1.2.4-r2 | docker.io/library/alpine:3.18 | a99a3b9349cccda16c787626594ca6fc1a1484eb8c5c49889f5345b6ee61840b |
| ld-musl-124.x86_64.so.1.debug | 1.2.4 | musl-dbg-1.2.4-r2 | docker.io/library/alpine:3.18 | a620bdc6789a0e984340b348095aac566f5351fbdbc5a767ef5a9d2db3bab2d2 |
| libc-124.a | 1.2.4 | musl-dev-1.2.4-r2 | docker.io/library/alpine:3.18 | 27933fb25c13300fceeccdf2df204580bb9ee863a0d2647e7cf93d2880ff2979 |
| ld-musl-123.x86_64.so.1 | 1.2.3 | musl-1.2.3-r5 | docker.io/library/alpine:3.16 | a99a3b9349cccda16c787626594ca6fc1a1484eb8c5c49889f5345b6ee61840b |
| ld-musl-123.x86_64.so.1.debug | 1.2.3 | musl-dbg-1.2.3-r5 | docker.io/library/alpine:3.16 | 36df7c5cd40a4579426bb6cba5651b6907504ef65ee8f96ec6b20cb8e55371b3 |
| libc-123.a | 1.2.3 | musl--dev-1.2.3-r5 | docker.io/library/alpine:3.16 | 83ecaf1399777b51ff31a9b22e99410b15da36300ebb351e7b12aafb1608b3df |


## Obtaining binaries

You can see which operating systems have what musl versions using [this query](https://pkgs.org/search/?q=musl).

I've been using alpine images. You can build the image with the following steps:


```dockerfile
FROM alpine:3.18
VOLUME /data

RUN apk update
RUN apk add musl-dbg
RUN apk add musl-dev
```

Then once you're inside of the container run the following:

```bash
VERSION=
mkdir -p /mount/musl/$VERSION
cp /lib/ld-musl-x86_64.so.1 /mount/musl/$VERSION
cp /usr/lib/debug/lib/ld-musl-x86_64.so.1.debug  /mount/musl/$VERSION
cp  /usr/lib/libc.a /mount/musl/$VERSION
sha256sum /mount/musl/$VERSION/*
```


