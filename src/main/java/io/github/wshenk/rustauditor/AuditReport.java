package io.github.wshenk.rustauditor;

import java.util.List;
import java.util.Map;

/**
 * The outcome of auditing one lockfile.
 *
 * @param lockfile          path of the audited lockfile (for display)
 * @param packageCount      number of packages in the lockfile
 * @param advisoryCount     number of advisories checked against
 * @param databaseRevision  advisory-db commit, or null
 * @param findings          vulnerabilities and warnings, most severe first
 * @param ignoredAdvisories ids of matching advisories suppressed with {@code --ignore}
 * @param duplicates        crates locked at more than one version, name to versions
 */
public record AuditReport(
        String lockfile,
        int packageCount,
        int advisoryCount,
        String databaseRevision,
        List<Finding> findings,
        List<String> ignoredAdvisories,
        Map<String, List<String>> duplicates) {

    public AuditReport {
        findings = List.copyOf(findings);
        ignoredAdvisories = List.copyOf(ignoredAdvisories);
        duplicates = Map.copyOf(duplicates);
    }

    public List<Finding> vulnerabilities() {
        return findings.stream().filter(f -> f.kind().isError()).toList();
    }

    public List<Finding> warnings() {
        return findings.stream().filter(f -> !f.kind().isError()).toList();
    }
}
