# Release channels and image tags

The server publishes to two channels. They mean exactly what the desktop
client's channels mean (`client/src/core/ReleaseSelection.h`) — same tag
grammar, same semver precedence — because a beta tester runs a beta
client against a beta server and "beta" has to be one idea, not two.

| Channel | Contains | Image tag |
|---|---|---|
| **stable** | published non-prerelease tags `vX.Y.Z` | `:latest` |
| **beta** | stable tags **and** prereleases `vX.Y.Z-rc.N`, `vX.Y.Z-beta.N` | `:latest-beta` |

Beta is a superset of stable, not a parallel track. A stable release that
is the newest thing in the repo takes `:latest-beta` too — otherwise
testers would be stranded on the last RC forever.

## Tag grammar

```
vMAJOR.MINOR.PATCH               stable      v0.0.44
vMAJOR.MINOR.PATCH-<pre>         prerelease  v0.0.44-rc.1, v0.1.0-beta.2
```

`<pre>` is dot-separated alphanumerics and hyphens. `+build` metadata is
accepted, ignored for ordering, and stripped from the image tag (`+` is
not legal in a docker tag).

Anything else — `0.0.44` with no `v`, `v0.0.44.1`, `v1.2` — **fails the
release job**. It does not publish an image with a guessed version.

## Image tags

Published to `ghcr.io/bsfchat/server`.

| Tag | Meaning | Moves? |
|---|---|---|
| `:X.Y.Z` | exactly that stable release | never |
| `:X.Y.Z-rc.N` | exactly that prerelease | never |
| `:X.Y` | highest stable patch on that minor line | within the line |
| `:latest` | **highest stable semver** | yes |
| `:latest-beta` | **highest of stable or prerelease** | yes |
| `:main` | tip of `main`, built on every push | yes |
| `:sha-<sha>` | one specific commit | never |

`:main` is a development tag — unreviewed, untagged, whatever landed
last. It was renamed from the old meaning of `:latest`; see
*What changed* below.

### The rule that matters

`:latest` is the **highest** stable version, not the most recently
pushed one.

Cutting a hotfix `v0.0.43` after `v0.0.44` has shipped must not drag
`:latest` back onto the older line, or every deployment tracking stable
silently downgrades on its next pull. The same applies to `:latest-beta`
and to `:X.Y`.

This is why the channel decision is
[`scripts/channel_tags.py`](../scripts/channel_tags.py) and not a
`docker/metadata-action` template: `type=semver` only sees the tag being
pushed, so it cannot know that a newer one already exists. The script
compares the pushed tag against every `v*` tag in the repository and
assigns a moving tag only when nothing outranks it.

Precedence is semver.org §11, matching the client:

* `0.0.44-rc.1 < 0.0.44` — a prerelease sorts **below** the release it
  precedes.
* `rc.10 > rc.9` — numeric identifiers compare numerically.
* numeric identifiers rank below alphanumeric ones (`1.0.0-1 < 1.0.0-alpha`).
* more identifiers wins when the shared ones are equal (`rc.1.1 > rc.1`).

Worked examples (`existing tags` includes the pushed one):

| Push | Existing | Publishes |
|---|---|---|
| `v0.0.44` | `v0.0.43` | `:0.0.44` `:0.0` `:latest` `:latest-beta` |
| `v0.0.45-rc.1` | `v0.0.44` | `:0.0.45-rc.1` `:latest-beta` |
| `v0.0.45` | `v0.0.45-rc.1`, `v0.0.44` | `:0.0.45` `:0.0` `:latest` `:latest-beta` |
| `v0.0.43` (hotfix) | `v0.0.44`, `v0.0.45` | `:0.0.43` only |
| `v1.2.4` | `v1.2.3`, `v2.0.0` | `:1.2.4` `:1.2` |
| `v0.0.44-rc.1` | `v0.0.44` | `:0.0.44-rc.1` only |

The table is executable: the same cases are in
`scripts/test_channel_tags.py`, which runs in CI and under
`ctest --test-dir build -R channel_tags`.

## Cutting a release

```sh
# stable
git tag -a v0.0.45 -m "v0.0.45"
git push origin v0.0.45

# release candidate (beta channel only)
git tag -a v0.0.45-rc.1 -m "v0.0.45-rc.1"
git push origin v0.0.45-rc.1
```

Annotated tags (`-a`), so the tag carries an author and a date.

The tag push triggers the `release` job, which:

1. validates the tag grammar and computes the channel assignment;
2. builds the image **once**, with `-DBSFCHAT_SERVER_VERSION` set from the
   tag, and pushes it under every applicable tag;
3. creates the GitHub Release, marked `prerelease: true` for any tag with
   a `-suffix`. That boolean is what the desktop client's updater filters
   on, so it is the authority for what is a beta — never the tag text.

Nothing is published from a branch push except `:main` and `:sha-<sha>`.

## Version reporting

The version is a `-DBSFCHAT_SERVER_VERSION` CMake define
(`cmake/Version.cmake`), falling back to `git describe --tags` and then
to `0.0.0-dev`. The fallback deliberately sorts below every real release:
an untagged build must not read as a shipped one.

It surfaces in three places:

```sh
# 1. the first line of the startup log
docker logs bsfchat-server | head -1
#   BSFChat server 0.0.44 (rev 1a2b3c4, stable channel)

# 2. the versions endpoint (additive; `versions` itself is unchanged)
curl -s http://localhost:8448/_matrix/client/versions | jq
#   { "versions": ["v1.12"],
#     "unstable_features": { "bsfchat.server": true },
#     "bsfchat.version": "0.0.44",
#     "bsfchat.revision": "1a2b3c4",
#     "bsfchat.channel": "stable" }

# 3. OCI labels, without starting anything
docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' \
  ghcr.io/bsfchat/server:latest
```

## What changed

`:latest` previously meant "tip of `main`" — it was pushed on every
branch push and had nothing to do with releases. Deployments tracking it
were on unreviewed code.

It now means the highest stable release. The old behaviour moved to
`:main`, which `deploy/.env.example` documents for developers.

**Operators pinned to `:latest` will move from tip-of-`main` to the
newest stable release the first time they pull after the first `vX.Y.Z`
tag is pushed.** Until that first stable tag exists there is no `:latest`
at all, so keep `BSFCHAT_TAG=main` (or pin a specific tag) until then.
