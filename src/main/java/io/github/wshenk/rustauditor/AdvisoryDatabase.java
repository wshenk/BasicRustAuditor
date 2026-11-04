package io.github.wshenk.rustauditor;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** An in-memory index of a local checkout of the RustSec advisory-db, keyed by crate name. */
public final class AdvisoryDatabase {

    public static final String DEFAULT_URL = "https://github.com/rustsec/advisory-db.git";

    private final Map<String, List<Advisory>> byPackage;
    private final int size;
    private final List<String> loadErrors;
    private final String revision;

    private AdvisoryDatabase(Map<String, List<Advisory>> byPackage, int size, List<String> loadErrors, String revision) {
        this.byPackage = byPackage;
        this.size = size;
        this.loadErrors = List.copyOf(loadErrors);
        this.revision = revision;
    }

    /** Builds a database directly from advisories (mainly useful for tests and embedding). */
    public static AdvisoryDatabase of(List<Advisory> advisories) {
        Map<String, List<Advisory>> map = new HashMap<>();
        for (Advisory a : advisories) {
            map.computeIfAbsent(a.packageName(), k -> new ArrayList<>()).add(a);
        }
        return new AdvisoryDatabase(map, advisories.size(), List.of(), null);
    }

    /** Loads every {@code crates/<name>/*.md} advisory from an advisory-db checkout. */
    public static AdvisoryDatabase load(Path dir) throws IOException {
        Path crates = dir.resolve("crates");
        if (!Files.isDirectory(crates)) {
            throw new IOException(dir + " does not look like an advisory-db checkout (no crates/ directory)");
        }
        List<Advisory> advisories = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(crates)) {
            files = walk.filter(p -> p.getFileName().toString().endsWith(".md")).sorted().toList();
        }
        for (Path file : files) {
            try {
                advisories.add(Advisory.parse(Files.readString(file, StandardCharsets.UTF_8)));
            } catch (RuntimeException e) {
                errors.add(dir.relativize(file) + ": " + e.getMessage());
            }
        }
        AdvisoryDatabase base = of(advisories);
        return new AdvisoryDatabase(base.byPackage, base.size, errors, gitRevision(dir));
    }

    /**
     * Clones the advisory-db into {@code dir}, or fast-forwards an existing clone. Requires {@code git} on the PATH.
     */
    public static void fetch(Path dir, String url, PrintStream log) throws IOException {
        if (Files.isDirectory(dir.resolve(".git"))) {
            log.println("Updating advisory database in " + dir);
            git(dir, "fetch", "--quiet", "--depth", "1", "origin", "HEAD");
            git(dir, "reset", "--quiet", "--hard", "FETCH_HEAD");
        } else if (Files.exists(dir) && !isEmptyDir(dir)) {
            log.println("Using advisory database in " + dir + " as-is (not a git clone)");
        } else {
            log.println("Fetching advisory database from " + url);
            Files.createDirectories(dir.toAbsolutePath().getParent());
            git(null, "clone", "--quiet", "--depth", "1", url, dir.toString());
        }
    }

    public List<Advisory> forPackage(String name) {
        return byPackage.getOrDefault(name, List.of());
    }

    /** Number of advisories loaded. */
    public int size() {
        return size;
    }

    /** Files that failed to parse; they are skipped rather than aborting the audit. */
    public List<String> loadErrors() {
        return loadErrors;
    }

    /** Short git commit of the checkout, or null if unknown. */
    public String revision() {
        return revision;
    }

    private static boolean isEmptyDir(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.findAny().isEmpty();
        }
    }

    private static String git(Path dir, String... args) throws IOException {
        List<String> cmd = new ArrayList<>();
        cmd.add("git");
        if (dir != null) {
            cmd.add("-C");
            cmd.add(dir.toString());
        }
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        try {
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!p.waitFor(10, TimeUnit.MINUTES)) {
                p.destroyForcibly();
                throw new IOException("git " + args[0] + " timed out");
            }
            if (p.exitValue() != 0) {
                throw new IOException("git " + String.join(" ", args) + " failed: " + out);
            }
            return out;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while running git", e);
        }
    }

    private static String gitRevision(Path dir) {
        if (!Files.isDirectory(dir.resolve(".git"))) {
            return null;
        }
        try {
            return git(dir, "rev-parse", "--short", "HEAD");
        } catch (IOException e) {
            return null;
        }
    }
}
