# musl libraries used by tests

|     name     | version |         pkgversion         |       docker tag/id       |                              sha256                              |
| ------------ | ------- | -------------------------- | ------------------------- | ---------------------------------------------------------------- |
| ld-musl-124.x86_64.so.1 | 1.2.4 | musl-1.2.4-r2 | docker.io/library/alpine:3.18 | a99a3b9349cccda16c787626594ca6fc1a1484eb8c5c49889f5345b6ee61840b |
| ld-musl-124.x86_64.so.1.debug | 1.2.4 | musl-dbg-1.2.4-r2 | docker.io/library/alpine:3.18 | a620bdc6789a0e984340b348095aac566f5351fbdbc5a767ef5a9d2db3bab2d2 |
| libc-124.a | 1.2.4 | musl-dev-1.2.4-r2 | docker.io/library/alpine:3.18 | 27933fb25c13300fceeccdf2df204580bb9ee863a0d2647e7cf93d2880ff2979 |


## Obtaining binaries

You can see which operating systems have what musl versions using [this query](https://pkgs.org/search/?q=musl).

We use the alpine packages for now. For simplicity sake to verify hashes, we include the .apk used
as the base point so it can be manually extracted if preferred.

```bash
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-1.2.4-r2.apk
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-dev-1.2.4-r2.apk
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-dbg-1.2.4-r2.apk
sha256sum *.apk
21c732ba7b1a7088a85d79a781076e3d5ec41b0bd52933ecb47bcc5804d6f501  musl-1.2.4-r2.apk
7ef08becf7225f2515d045d25082aa9fe00282e1224bc3f816b5062741c958ec  musl-dev-1.2.4-r2.apk
32b9837354e254e06b2f5429f0a9753580614bd0272ad8db0f5798544e20e9a7  musl-dbg-1.2.4-r2.apk
tar -xvzf musl-1.2.4-r2.apk
tar -xvzf musl-dev-1.2.4-r2.apk
tar -xzvf musl-dbg-1.2.4-r2.apk
```

We are interested in the resulting files:

* `lib/*`
* `usr/lib/*`

These are placed into `tests/gdb-tests/tests/binaries/musls/<version>` folders, and adjusted with symlinks so it's
easier to find the exact versions. The tweaked names are as follows:

```bash
❯ ls -l lib/
.rwxr-xr-x 617k aa 13  5月 15:34  ld-musl-124-x86_64.so.1
.rwxr-xr-x 3.0M aa 13  5月 15:34  ld-musl-124-x86_64.so.1.debug
lrwxrwxrwx    - aa 13  5月 15:34  ld-musl-x86_64.so.1 -> ld-musl-124-x86_64.so.1
lrwxrwxrwx    - aa 13  5月 15:34  ld-musl-x86_64.so.1.debug -> ld-musl-124-x86_64.so.1.debug
.rw-r--r-- 9.1M aa 13  5月 15:34  libc-124.a
lrwxrwxrwx    - aa 13  5月 15:34  libc.a -> libc-124.a
```
