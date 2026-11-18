# Tools

| | |
|---|---|
| [fetch/](fetch/) | downloads and pins the binaries BOND embeds; the rest of this page |
| [handread/](handread/) | decrypts a container without BOND, from NERDME §11; imports nothing of BOND's, and is tested against it |
| [fixtures/](fixtures/) | writes candidate golden fixtures and known-answer vectors for a format revision |

## Tool fetcher

Everything BOND embeds but does not write itself lives here: the pinned manifest, the fetcher that acts on it, and
the licence texts that come back with the downloads.

```
go run ./tools/fetch                       # fetch what is missing
go run ./tools/fetch --check               # verify what is here, download nothing
go run ./tools/fetch --target linux/amd64  # only what a build for one platform embeds
```

`build.sh` cross-compiles every platform and so fetches everything. `--target` is for a build on and for a single
platform, such as a distribution package: it downloads only the packages that platform's binaries come from, and
`--check` with it verifies only those. A download already in `download-cache/` under its URL's file name is used
when it hashes to the manifest's value, so a packager can supply the files and the fetcher goes online for nothing.
`--target` cannot be combined with `--update-hashes`, which has to see every platform.

| | |
|---|---|
| [manifest.json](manifest.json) | what to fetch, from where, and what it must hash to |
| [fetch/](fetch/) | the fetcher |
| `licenses/` | one licence per installed binary, fetched – not committed |
| `download-cache/` | the raw downloads, hash-validated – not committed |

Nothing is downloaded that is not named in the manifest, and nothing is installed that does not hash to the value
recorded there: every package, every binary and every licence is pinned. A mirror serving something else, or a
truncated download, fails the build rather than ending up inside a backup tool.

## Adding a tool

A new key under `tools`, with its own `version`, its own `binDir` – wherever the package that embeds it wants the
files – and its packages and binaries. No code changes for anything `tar` can open. A tool published as a plain
executable rather than an archive sets `"bare": true` on its package and is installed by copying.

## Bumping a version

Change `version` and the URLs, then review the diffs from 

```
go run ./tools/fetch --update-hashes
```
