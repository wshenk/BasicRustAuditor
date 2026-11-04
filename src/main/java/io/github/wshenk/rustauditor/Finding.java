package io.github.wshenk.rustauditor;

import java.util.List;

/**
 * One problem found in a lockfile.
 *
 * @param kind       what was found
 * @param pkg        the affected package
 * @param advisory   the matching advisory, or null for lockfile hygiene findings
 * @param message    a one-line description
 * @param dependencyPath how the package is pulled in, from the package itself up to a root crate
 */
public record Finding(Kind kind, CargoLock.Package pkg, Advisory advisory, String message, List<String> dependencyPath) {

    public Finding {
        dependencyPath = List.copyOf(dependencyPath);
    }

    public enum Kind {
        /** A security advisory affects the locked version. */
        VULNERABILITY("vulnerability"),
        /** Informational advisory: the crate is no longer maintained. */
        UNMAINTAINED("unmaintained"),
        /** Informational advisory: the crate exposes unsound APIs. */
        UNSOUND("unsound"),
        /** Any other informational advisory (e.g. "notice"). */
        NOTICE("notice"),
        /** The package comes from a git repository rather than a registry. */
        GIT_SOURCE("git-source"),
        /** The package comes from a registry other than crates.io (not covered by RustSec). */
        ALTERNATE_REGISTRY("alternate-registry"),
        /** A registry package has no checksum recorded in the lockfile. */
        MISSING_CHECKSUM("missing-checksum");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        public boolean isError() {
            return this == VULNERABILITY;
        }
    }

    /** A suggested fix derived from the advisory's patched versions. */
    public String solution() {
        if (advisory == null) {
            return null;
        }
        if (advisory.patched().isEmpty()) {
            return "no fixed release is available; consider an alternative crate";
        }
        return "upgrade to " + String.join(" or ", advisory.patched().stream().map(VersionReq::toString).toList());
    }
}
