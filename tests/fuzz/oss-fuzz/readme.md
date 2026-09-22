# OSS-Fuzz / ClusterFuzzLite integration

Three files, and none of them live here in the end: OSS-Fuzz builds from a
`projects/<name>/` directory in its own repository, and what is kept here is the
copy that is edited and tested. `build.sh` is the only one with logic in it.

## What the build does

`build.sh` puts a framework-only host project around `core/` — the listing from
`INSTALL.md` §3 — because `core/` does not configure on its own: the
`find_package` calls for PCRE2, OpenSSL, libxml2 and the rest belong to the
host. It then builds with `BUILD_FUZZERS=yes` and copies to `$OUT`:

* the target binaries,
* `fuzz_<target>_seed_corpus.zip` from `tests/fuzz/corpus/<target>/`,
* `fuzz_<target>.dict` from `tests/fuzz/dict/`, where one exists,
* `lib/libcwfr_framework.so*`.

That last one is not optional. The framework is a shared library, the targets
link it dynamically, and `$OUT` is copied somewhere else entirely before
anything in it runs — so the library travels with the binaries and they are
linked with `-Wl,-rpath,$ORIGIN/lib` to find it there.

HTTP/3 is off: it needs OpenSSL 3.5 and the base image has an older one. That
is also why `BUILD_FUZZERS` no longer implies `INCLUDE_HTTP3` — the six targets
this builds (`huffman`, `hpack`, `cookie`, `urlencoded`, `multipart`,
`request`) touch no QUIC. The seven QUIC and HTTP/3 targets still build
locally, where OpenSSL is new enough.

## Testing it without submitting anything

The official way is `infra/helper.py` from a clone of the OSS-Fuzz repository.
The short way, which is what the files here were checked with:

```bash
docker run --rm -v "$PWD:/src/cwfr" -v /tmp/out:/out \
    -e SANITIZER=address -e FUZZING_ENGINE=libfuzzer -e FUZZING_LANGUAGE=c \
    gcr.io/oss-fuzz-base/base-builder bash -c '
        apt-get update -qq && apt-get install -y -qq --no-install-recommends \
            cmake ninja-build zip libpcre2-dev zlib1g-dev libssl-dev \
            libxml2-dev libidn2-dev libunistring-dev
        cp /src/cwfr/tests/fuzz/oss-fuzz/build.sh /src/build.sh
        compile'

docker run --rm -v /tmp/out:/out gcr.io/oss-fuzz-base/base-runner bash -c '
    cd /tmp && mkdir -p c && unzip -qo /out/fuzz_request_seed_corpus.zip -d c
    /out/fuzz_request -dict=/out/fuzz_request.dict -runs=40000 c'
```

`compile` rather than `build.sh` directly: it is the wrapper that assembles
`/usr/lib/libFuzzingEngine.a` and puts the sanitizer into `CFLAGS`. Running
`build.sh` on its own fails at the link with the archive missing, which is a
property of the shortcut and not of the script.

## Before submitting

`project.yaml` has a `primary_contact` placeholder. OSS-Fuzz requires a real
address with commit access to the project, and reports go there.

Be aware of the acceptance bar: OSS-Fuzz takes projects with a significant user
base or a place in critical infrastructure, and a small framework may simply
not be accepted. **ClusterFuzzLite** needs no acceptance — it runs the same
`build.sh` inside the project's own GitHub Actions, on pull requests and on a
schedule, and is the realistic option for a project this size.
