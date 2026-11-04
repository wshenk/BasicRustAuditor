package io.github.wshenk.rustauditor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Checks a {@link CargoLock} against an {@link AdvisoryDatabase} plus a few lockfile hygiene rules. */
public final class Auditor {

    private final AdvisoryDatabase database;
    private final Set<String> ignored;

    /**
     * @param database advisories to check against
     * @param ignored  advisory ids or aliases (e.g. {@code RUSTSEC-2020-0071}, {@code CVE-2020-26235}) to suppress
     */
    public Auditor(AdvisoryDatabase database, Set<String> ignored) {
        this.database = database;
        this.ignored = Set.copyOf(ignored);
    }

    public AuditReport audit(CargoLock lock, String lockfileName) {
        DependencyGraph graph = new DependencyGraph(lock);
        List<Finding> findings = new ArrayList<>();
        Set<String> ignoredHits = new LinkedHashSet<>();

        for (CargoLock.Package pkg : lock.packages()) {
            if (pkg.isCratesIo()) {
                checkAdvisories(pkg, graph, findings, ignoredHits);
            }
            if (pkg.isGit()) {
                findings.add(new Finding(Finding.Kind.GIT_SOURCE, pkg, null,
                        "pulled from git (" + pkg.source() + "); not covered by the advisory database",
                        graph.pathToRoot(pkg)));
            } else if (pkg.isRegistry() && !pkg.isCratesIo()) {
                findings.add(new Finding(Finding.Kind.ALTERNATE_REGISTRY, pkg, null,
                        "pulled from a non-crates.io registry (" + pkg.source() + "); not covered by the advisory database",
                        graph.pathToRoot(pkg)));
            }
            if (pkg.isRegistry() && (pkg.checksum() == null || pkg.checksum().isBlank())) {
                findings.add(new Finding(Finding.Kind.MISSING_CHECKSUM, pkg, null,
                        "registry package has no checksum in the lockfile", graph.pathToRoot(pkg)));
            }
        }

        findings.sort(Comparator
                .comparing((Finding f) -> f.kind().ordinal())
                .thenComparing(f -> -score(f))
                .thenComparing(f -> f.pkg().name())
                .thenComparing(f -> f.advisory() == null ? "" : f.advisory().id()));

        return new AuditReport(lockfileName, lock.packages().size(), database.size(), database.revision(),
                findings, List.copyOf(ignoredHits), duplicates(lock));
    }

    private void checkAdvisories(CargoLock.Package pkg, DependencyGraph graph, List<Finding> out, Set<String> ignoredHits) {
        List<Advisory> candidates = database.forPackage(pkg.name());
        if (candidates.isEmpty()) {
            return;
        }
        SemVer version;
        try {
            version = SemVer.parse(pkg.version());
        } catch (IllegalArgumentException e) {
            return; // Cargo only locks valid semver, so this is effectively unreachable
        }
        for (Advisory a : candidates) {
            if (a.isWithdrawn() || !a.affects(version)) {
                continue;
            }
            if (ignored.stream().anyMatch(a::hasId)) {
                ignoredHits.add(a.id());
                continue;
            }
            Finding.Kind kind = a.isVulnerability() ? Finding.Kind.VULNERABILITY : switch (a.informational()) {
                case "unmaintained" -> Finding.Kind.UNMAINTAINED;
                case "unsound" -> Finding.Kind.UNSOUND;
                default -> Finding.Kind.NOTICE;
            };
            out.add(new Finding(kind, pkg, a, a.title(), graph.pathToRoot(pkg)));
        }
    }

    private static double score(Finding f) {
        return f.advisory() == null ? 0 : f.advisory().cvssScore().orElse(0);
    }

    private static Map<String, List<String>> duplicates(CargoLock lock) {
        Map<String, List<String>> versions = new TreeMap<>();
        for (CargoLock.Package p : lock.packages()) {
            versions.computeIfAbsent(p.name(), k -> new ArrayList<>()).add(p.version());
        }
        versions.values().removeIf(v -> v.size() < 2);
        return versions;
    }

    /** Reverse dependency edges, used to explain why a crate is in the tree. */
    static final class DependencyGraph {

        private final Map<String, List<CargoLock.Package>> byName = new HashMap<>();
        private final Map<CargoLock.Package, List<CargoLock.Package>> dependents = new LinkedHashMap<>();

        DependencyGraph(CargoLock lock) {
            for (CargoLock.Package p : lock.packages()) {
                byName.computeIfAbsent(p.name(), k -> new ArrayList<>()).add(p);
                dependents.put(p, new ArrayList<>());
            }
            for (CargoLock.Package p : lock.packages()) {
                for (String dep : p.dependencies()) {
                    CargoLock.Package target = resolve(dep);
                    if (target != null) {
                        dependents.get(target).add(p);
                    }
                }
            }
        }

        /**
         * Resolves a lockfile dependency reference: {@code name}, {@code name version} or
         * {@code name version (source)}; the extra parts only appear when the name is ambiguous.
         */
        private CargoLock.Package resolve(String ref) {
            String[] parts = ref.split(" ", 3);
            List<CargoLock.Package> candidates = byName.getOrDefault(parts[0], List.of());
            if (parts.length > 1) {
                candidates = candidates.stream().filter(c -> c.version().equals(parts[1])).toList();
            }
            if (parts.length > 2 && candidates.size() > 1) {
                String source = parts[2].replaceAll("^\\(|\\)$", "");
                candidates = candidates.stream().filter(c -> source.equals(c.source())).toList();
            }
            return candidates.isEmpty() ? null : candidates.get(0);
        }

        /** Shortest chain of dependents from {@code pkg} up to a crate nothing else depends on. */
        List<String> pathToRoot(CargoLock.Package pkg) {
            Map<CargoLock.Package, CargoLock.Package> parent = new HashMap<>();
            Deque<CargoLock.Package> queue = new ArrayDeque<>();
            queue.add(pkg);
            parent.put(pkg, null);
            CargoLock.Package root = pkg;
            while (!queue.isEmpty()) {
                CargoLock.Package current = queue.poll();
                List<CargoLock.Package> up = dependents.getOrDefault(current, List.of());
                if (up.isEmpty()) {
                    root = current;
                    break;
                }
                for (CargoLock.Package d : up) {
                    if (!parent.containsKey(d)) {
                        parent.put(d, current);
                        queue.add(d);
                    }
                }
            }
            List<String> path = new ArrayList<>();
            for (CargoLock.Package p = root; p != null; p = parent.get(p)) {
                path.add(0, p.id());
            }
            return path;
        }
    }
}
