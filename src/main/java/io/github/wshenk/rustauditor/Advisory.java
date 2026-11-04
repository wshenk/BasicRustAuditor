package io.github.wshenk.rustauditor;

import io.github.wshenk.rustauditor.toml.MiniToml;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;

/**
 * A RustSec advisory, parsed from the Markdown files in the
 * <a href="https://github.com/rustsec/advisory-db">advisory-db</a> (TOML front matter in a
 * {@code ```toml} fence followed by a {@code # Title} heading and description).
 */
public record Advisory(
        String id,
        String packageName,
        String title,
        String date,
        String url,
        List<String> aliases,
        List<String> categories,
        String informational,
        String withdrawn,
        String cvss,
        List<VersionReq> patched,
        List<VersionReq> unaffected) {

    public Advisory {
        aliases = List.copyOf(aliases);
        categories = List.copyOf(categories);
        patched = List.copyOf(patched);
        unaffected = List.copyOf(unaffected);
    }

    /** True if {@code version} is neither patched nor unaffected. */
    public boolean affects(SemVer version) {
        for (VersionReq r : patched) {
            if (r.matches(version)) {
                return false;
            }
        }
        for (VersionReq r : unaffected) {
            if (r.matches(version)) {
                return false;
            }
        }
        return true;
    }

    /** Vulnerabilities have no {@code informational} kind (unmaintained, unsound, notice, ...). */
    public boolean isVulnerability() {
        return informational == null;
    }

    public boolean isWithdrawn() {
        return withdrawn != null;
    }

    public OptionalDouble cvssScore() {
        return Cvss.baseScore(cvss);
    }

    /** Qualitative severity derived from the CVSS v3 score, or {@code "unknown"}. */
    public String severity() {
        OptionalDouble score = cvssScore();
        return score.isPresent() ? Cvss.severity(score.getAsDouble()) : "unknown";
    }

    /** True if the given id equals this advisory's id or one of its aliases (e.g. a CVE or GHSA id). */
    public boolean hasId(String candidate) {
        return id.equalsIgnoreCase(candidate) || aliases.stream().anyMatch(a -> a.equalsIgnoreCase(candidate));
    }

    /** Parses an advisory Markdown file. */
    public static Advisory parse(String markdown) {
        String text = markdown.replace("\r\n", "\n");
        String open = "```toml\n";
        int start = text.indexOf(open);
        int end = start < 0 ? -1 : text.indexOf("\n```", start + open.length());
        if (start < 0 || end < 0) {
            throw new IllegalArgumentException("missing ```toml front matter");
        }
        Map<String, Object> doc = MiniToml.parse(text.substring(start + open.length(), end + 1));
        Map<String, Object> adv = MiniToml.getTable(doc, "advisory");
        if (adv == null) {
            throw new IllegalArgumentException("missing [advisory] table");
        }
        String id = MiniToml.getString(adv, "id");
        String pkg = MiniToml.getString(adv, "package");
        if (id == null || pkg == null) {
            throw new IllegalArgumentException("advisory is missing id or package");
        }
        String title = MiniToml.getString(adv, "title"); // older advisories kept the title here
        if (title == null) {
            title = heading(text.substring(end + 4));
        }
        Map<String, Object> versions = MiniToml.getTable(doc, "versions");
        return new Advisory(
                id,
                pkg,
                title == null ? "" : title,
                MiniToml.getString(adv, "date"),
                MiniToml.getString(adv, "url"),
                MiniToml.getStringList(adv, "aliases"),
                MiniToml.getStringList(adv, "categories"),
                MiniToml.getString(adv, "informational"),
                MiniToml.getString(adv, "withdrawn"),
                MiniToml.getString(adv, "cvss"),
                MiniToml.getStringList(versions, "patched").stream().map(VersionReq::parse).toList(),
                MiniToml.getStringList(versions, "unaffected").stream().map(VersionReq::parse).toList());
    }

    private static String heading(String body) {
        for (String line : body.split("\n")) {
            if (line.startsWith("# ")) {
                return line.substring(2).trim();
            }
        }
        return null;
    }
}
