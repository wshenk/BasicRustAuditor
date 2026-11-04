# BasicRustAuditor

A basic dependency auditor for Rust projects, written in Java 21 and built with Gradle.
It reads a project's `Cargo.lock`, checks every locked crate against the
[RustSec advisory database](https://github.com/rustsec/advisory-db) (the same data `cargo audit` uses),
and flags a few lockfile hygiene issues. It has no runtime dependencies beyond the JDK and `git`.

## What it checks

| Finding              | Level   | Meaning                                                              |
|----------------------|---------|----------------------------------------------------------------------|
| `vulnerability`      | error   | A RustSec security advisory affects the locked version               |
| `unmaintained`       | warning | Informational advisory: crate is no longer maintained               |
| `unsound`            | warning | Informational advisory: crate exposes unsound APIs                  |
| `notice`             | warning | Any other informational advisory                                    |
| `git-source`         | warning | Crate comes from a git repo, so advisories can't be matched         |
| `alternate-registry` | warning | Crate comes from a non-crates.io registry, so advisories can't be matched |
| `missing-checksum`   | warning | A registry crate has no checksum in `Cargo.lock`                    |

It also prints crates that are locked at more than one version. For each advisory it shows the
CVSS v3 severity, aliases (CVE/GHSA), the fix version and the dependency chain that pulls the
crate in. Withdrawn advisories are skipped.

## Build

```sh
./gradlew build        # compile and run tests
./gradlew installDist  # build/install/basic-rust-auditor/bin/basic-rust-auditor
```

The jar has no dependencies, so `java -jar build/libs/basic-rust-auditor-*.jar` also works.

## Usage

```sh
basic-rust-auditor path/to/rust-project        # or a path to a Cargo.lock
basic-rust-auditor --format json .              # machine-readable output
basic-rust-auditor --ignore RUSTSEC-2020-0071 --ignore CVE-2021-25900 .
basic-rust-auditor --deny-warnings .            # fail on warnings too
basic-rust-auditor --no-fetch --db ./advisory-db .  # offline, with your own checkout
```

On the first run the advisory database is cloned with `git` into
`~/.cache/basic-rust-auditor/advisory-db`, and it is updated on every run after that
(use `--no-fetch` to skip this). If an update fails, the existing copy is used.

Exit status: `0` no findings that fail the run, `1` vulnerabilities found (or warnings with
`--deny-warnings`), `2` usage or I/O error. That makes it suitable as a CI gate.

Example output:

```
Scanned 39 crates in demo/Cargo.lock against 1386 advisories (advisory-db @ 965bf9a)

error[RUSTSEC-2021-0003] smallvec 1.6.0: Buffer overflow in SmallVec::insert_many
  severity: critical (CVSS 9.8)
  date:     2021-01-08
  aliases:  CVE-2021-25900, GHSA-43w2-9j62-hq99
  url:      https://github.com/servo/rust-smallvec/issues/252
  fix:      upgrade to >= 0.6.14, < 1.0.0 or >= 1.6.1
  via:      smallvec 1.6.0 <- demo 0.1.0

warning[RUSTSEC-2022-0022] hyper 0.14.10: Parser creates invalid uninitialized value
  kind:     unsound
  ...

3 vulnerabilities and 1 warning found.
```

## Limitations

- Advisories are matched on crate name and version only. Platform (`os`/`arch`) and
  affected-function details are not used to filter results, so some reports may not apply to your build.
- Yanked crates are not detected (that needs the crates.io index).
- CVSS v4 vectors are not scored and show as `unknown` severity.

## Layout

- `toml/MiniToml` – small TOML parser for `Cargo.lock` and advisory front matter
- `SemVer`, `VersionReq` – Cargo-compatible version and requirement matching
- `CargoLock`, `Advisory`, `AdvisoryDatabase` – data models and loading
- `Auditor` – runs the checks and works out dependency paths
- `ReportRenderer` – text and JSON output; `Main` – CLI
