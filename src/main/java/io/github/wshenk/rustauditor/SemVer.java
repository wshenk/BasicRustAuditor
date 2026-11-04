package io.github.wshenk.rustauditor;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A semantic version as used by Cargo ({@code MAJOR.MINOR.PATCH[-PRE][+BUILD]}). Build metadata is ignored. */
public record SemVer(long major, long minor, long patch, List<String> pre) implements Comparable<SemVer> {

    private static final Pattern PATTERN = Pattern.compile(
            "v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?");

    public SemVer {
        pre = List.copyOf(pre);
    }

    public static SemVer of(long major, long minor, long patch) {
        return new SemVer(major, minor, patch, List.of());
    }

    /** Parses a full version string such as {@code 1.2.3} or {@code 1.0.0-beta.2}. */
    public static SemVer parse(String text) {
        Matcher m = PATTERN.matcher(text.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid version: '" + text + "'");
        }
        List<String> pre = m.group(4) == null ? List.of() : List.of(m.group(4).split("\\."));
        return new SemVer(Long.parseLong(m.group(1)), Long.parseLong(m.group(2)), Long.parseLong(m.group(3)), pre);
    }

    public boolean isPrerelease() {
        return !pre.isEmpty();
    }

    /** True when both versions share {@code major.minor.patch}. */
    boolean sameCore(SemVer other) {
        return major == other.major && minor == other.minor && patch == other.patch;
    }

    @Override
    public int compareTo(SemVer o) {
        int c = Long.compare(major, o.major);
        if (c == 0) {
            c = Long.compare(minor, o.minor);
        }
        if (c == 0) {
            c = Long.compare(patch, o.patch);
        }
        return c != 0 ? c : comparePre(pre, o.pre);
    }

    private static int comparePre(List<String> a, List<String> b) {
        if (a.isEmpty() || b.isEmpty()) {
            // A release sorts after any of its pre-releases.
            return Boolean.compare(a.isEmpty(), b.isEmpty());
        }
        for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
            String x = a.get(i);
            String y = b.get(i);
            boolean xn = isNumeric(x);
            boolean yn = isNumeric(y);
            int c;
            if (xn && yn) {
                c = x.length() != y.length() ? Integer.compare(x.length(), y.length()) : x.compareTo(y);
            } else if (xn != yn) {
                c = xn ? -1 : 1; // numeric identifiers sort before alphanumeric ones
            } else {
                c = x.compareTo(y);
            }
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(a.size(), b.size());
    }

    private static boolean isNumeric(String s) {
        return !s.isEmpty() && s.chars().allMatch(Character::isDigit);
    }

    @Override
    public String toString() {
        String core = major + "." + minor + "." + patch;
        return pre.isEmpty() ? core : core + "-" + String.join(".", pre);
    }
}
