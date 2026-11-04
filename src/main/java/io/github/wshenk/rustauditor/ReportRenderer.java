package io.github.wshenk.rustauditor;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalDouble;

/** Renders an {@link AuditReport} as human-readable text or JSON. */
public final class ReportRenderer {

    private ReportRenderer() {
    }

    // ---- text ------------------------------------------------------------------------------

    public static String text(AuditReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scanned ").append(r.packageCount()).append(" crates in ").append(r.lockfile())
                .append(" against ").append(r.advisoryCount()).append(" advisories");
        if (r.databaseRevision() != null) {
            sb.append(" (advisory-db @ ").append(r.databaseRevision()).append(')');
        }
        sb.append("\n");

        for (Finding f : r.findings()) {
            sb.append("\n");
            Advisory a = f.advisory();
            String level = f.kind().isError() ? "error" : "warning";
            sb.append(level).append('[').append(a != null ? a.id() : f.kind().label()).append("] ")
                    .append(f.pkg().id()).append(": ").append(f.message()).append("\n");
            if (a != null) {
                if (!f.kind().isError()) {
                    sb.append("  kind:     ").append(f.kind().label()).append("\n");
                }
                OptionalDouble score = a.cvssScore();
                if (score.isPresent()) {
                    sb.append("  severity: ").append(a.severity())
                            .append(String.format(Locale.ROOT, " (CVSS %.1f)", score.getAsDouble())).append("\n");
                }
                if (a.date() != null) {
                    sb.append("  date:     ").append(a.date()).append("\n");
                }
                if (!a.aliases().isEmpty()) {
                    sb.append("  aliases:  ").append(String.join(", ", a.aliases())).append("\n");
                }
                sb.append("  url:      ").append(a.url() != null ? a.url() : "https://rustsec.org/advisories/" + a.id())
                        .append("\n");
                sb.append("  fix:      ").append(f.solution()).append("\n");
            }
            if (f.dependencyPath().size() > 1) {
                sb.append("  via:      ").append(String.join(" <- ", f.dependencyPath())).append("\n");
            }
        }

        if (!r.duplicates().isEmpty()) {
            sb.append("\nnote: ").append(r.duplicates().size()).append(" crate(s) are locked at more than one version:\n");
            r.duplicates().entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e ->
                    sb.append("  ").append(e.getKey()).append(": ").append(String.join(", ", e.getValue())).append("\n"));
        }
        if (!r.ignoredAdvisories().isEmpty()) {
            sb.append("\nnote: ignored ").append(String.join(", ", r.ignoredAdvisories())).append("\n");
        }

        int vulns = r.vulnerabilities().size();
        int warns = r.warnings().size();
        sb.append("\n");
        if (vulns == 0 && warns == 0) {
            sb.append("No problems found.\n");
        } else {
            sb.append(vulns).append(vulns == 1 ? " vulnerability" : " vulnerabilities").append(" and ")
                    .append(warns).append(warns == 1 ? " warning" : " warnings").append(" found.\n");
        }
        return sb.toString();
    }

    // ---- JSON ------------------------------------------------------------------------------

    public static String json(AuditReport r) {
        Json j = new Json();
        j.open('{');
        j.field("lockfile").string(r.lockfile());
        j.field("packages").raw(Integer.toString(r.packageCount()));
        j.field("advisories").raw(Integer.toString(r.advisoryCount()));
        j.field("databaseRevision").string(r.databaseRevision());
        j.field("summary").open('{');
        j.field("vulnerabilities").raw(Integer.toString(r.vulnerabilities().size()));
        j.field("warnings").raw(Integer.toString(r.warnings().size()));
        j.close('}');
        j.field("findings").open('[');
        for (Finding f : r.findings()) {
            j.element().open('{');
            j.field("kind").string(f.kind().label());
            j.field("crate").string(f.pkg().name());
            j.field("version").string(f.pkg().version());
            j.field("source").string(f.pkg().source());
            j.field("message").string(f.message());
            Advisory a = f.advisory();
            if (a != null) {
                j.field("advisory").open('{');
                j.field("id").string(a.id());
                j.field("title").string(a.title());
                j.field("date").string(a.date());
                j.field("url").string(a.url());
                j.field("cvss").string(a.cvss());
                OptionalDouble score = a.cvssScore();
                j.field("score").raw(score.isPresent() ? Double.toString(score.getAsDouble()) : "null");
                j.field("severity").string(a.severity());
                j.field("aliases").strings(a.aliases());
                j.field("categories").strings(a.categories());
                j.field("patched").strings(a.patched().stream().map(VersionReq::toString).toList());
                j.field("unaffected").strings(a.unaffected().stream().map(VersionReq::toString).toList());
                j.close('}');
                j.field("solution").string(f.solution());
            }
            j.field("dependencyPath").strings(f.dependencyPath());
            j.close('}');
        }
        j.close(']');
        j.field("ignored").strings(r.ignoredAdvisories());
        j.field("duplicates").open('{');
        r.duplicates().entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach(e -> j.field(e.getKey()).strings(e.getValue()));
        j.close('}');
        j.close('}');
        return j.toString() + "\n";
    }

    /** A tiny pretty-printing JSON writer. */
    private static final class Json {
        private final StringBuilder sb = new StringBuilder();
        private int depth;
        private boolean first = true;

        Json open(char c) {
            sb.append(c);
            depth++;
            first = true;
            return this;
        }

        Json close(char c) {
            depth--;
            if (!first) {
                newline();
            }
            sb.append(c);
            first = false;
            return this;
        }

        Json element() {
            if (!first) {
                sb.append(',');
            }
            newline();
            first = false;
            return this;
        }

        Json field(String name) {
            element();
            quote(name);
            sb.append(": ");
            return this;
        }

        Json raw(String value) {
            sb.append(value);
            return this;
        }

        Json string(String value) {
            if (value == null) {
                sb.append("null");
            } else {
                quote(value);
            }
            return this;
        }

        Json strings(List<String> values) {
            sb.append('[');
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                quote(values.get(i));
            }
            sb.append(']');
            return this;
        }

        private void newline() {
            sb.append('\n').append("  ".repeat(depth));
        }

        private void quote(String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                    }
                }
            }
            sb.append('"');
        }

        @Override
        public String toString() {
            return sb.toString();
        }
    }
}
