package io.github.wshenk.rustauditor;

import io.github.wshenk.rustauditor.toml.MiniToml;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The resolved packages listed in a {@code Cargo.lock} file (lockfile versions 1 through 4). */
public record CargoLock(int lockfileVersion, List<Package> packages) {

    /** The crates.io registry source strings used by Cargo (git index and sparse index). */
    public static final List<String> CRATES_IO_SOURCES = List.of(
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/");

    public CargoLock {
        packages = List.copyOf(packages);
    }

    /** One {@code [[package]]} entry. {@code source} is null for workspace members and path dependencies. */
    public record Package(String name, String version, String source, String checksum, List<String> dependencies) {

        public Package {
            dependencies = List.copyOf(dependencies);
        }

        public boolean isLocal() {
            return source == null;
        }

        public boolean isCratesIo() {
            return source != null && CRATES_IO_SOURCES.contains(source);
        }

        public boolean isGit() {
            return source != null && source.startsWith("git+");
        }

        public boolean isRegistry() {
            return source != null && (source.startsWith("registry+") || source.startsWith("sparse+"));
        }

        /** {@code name version}, e.g. {@code serde 1.0.200}. */
        public String id() {
            return name + " " + version;
        }
    }

    public static CargoLock read(Path file) throws IOException {
        return parse(Files.readString(file, StandardCharsets.UTF_8));
    }

    public static CargoLock parse(String text) {
        Map<String, Object> doc = MiniToml.parse(text);
        int version = doc.get("version") instanceof Long l ? l.intValue() : 1;
        // Lockfile v1 kept checksums in a [metadata] table keyed "checksum <name> <version> (<source>)".
        Map<String, Object> metadata = MiniToml.getTable(doc, "metadata");

        List<Package> packages = new ArrayList<>();
        for (Map<String, Object> p : MiniToml.getTableList(doc, "package")) {
            String name = MiniToml.getString(p, "name");
            String ver = MiniToml.getString(p, "version");
            if (name == null || ver == null) {
                throw new IllegalArgumentException("[[package]] entry without name or version");
            }
            String source = MiniToml.getString(p, "source");
            String checksum = MiniToml.getString(p, "checksum");
            if (checksum == null && metadata != null && source != null) {
                checksum = MiniToml.getString(metadata, "checksum " + name + " " + ver + " (" + source + ")");
            }
            packages.add(new Package(name, ver, source, checksum, MiniToml.getStringList(p, "dependencies")));
        }
        return new CargoLock(version, packages);
    }
}
