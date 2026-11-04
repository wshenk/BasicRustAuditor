package io.github.wshenk.rustauditor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A Cargo-style version requirement such as {@code ">= 1.2.3, < 1.3.0"}, {@code "^0.4"} or {@code "~1.2"}.
 *
 * <p>Follows Cargo's rules: a bare version means caret, partial versions and wildcards are expanded,
 * and a pre-release version only matches when one of the comparators names a pre-release of the
 * same {@code major.minor.patch}.
 */
public final class VersionReq {

    private enum Op { EQ, GT, GE, LT, LE, TILDE, CARET }

    private record Bound(Op op, SemVer version) {
        boolean test(SemVer v) {
            int c = v.compareTo(version);
            return switch (op) {
                case EQ -> c == 0;
                case GT -> c > 0;
                case GE -> c >= 0;
                case LT -> c < 0;
                case LE -> c <= 0;
                default -> throw new IllegalStateException(op.name());
            };
        }
    }

    private static final Pattern COMPARATOR = Pattern.compile("(>=|<=|=|>|<|~|\\^)?\\s*(.+)");
    private static final Pattern PARTIAL = Pattern.compile(
            "v?(\\d+|[*xX])(?:\\.(\\d+|[*xX]))?(?:\\.(\\d+|[*xX]))?(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?");

    private final String text;
    private final List<Bound> bounds = new ArrayList<>();
    private final List<SemVer> prereleaseAnchors = new ArrayList<>();

    private VersionReq(String text) {
        this.text = text.trim();
    }

    public static VersionReq parse(String text) {
        VersionReq req = new VersionReq(text);
        if (req.text.isEmpty()) {
            throw new IllegalArgumentException("empty version requirement");
        }
        for (String part : req.text.split(",")) {
            req.addComparator(part.trim());
        }
        return req;
    }

    public boolean matches(SemVer v) {
        for (Bound b : bounds) {
            if (!b.test(v)) {
                return false;
            }
        }
        if (v.isPrerelease()) {
            return prereleaseAnchors.stream().anyMatch(v::sameCore);
        }
        return true;
    }

    private void addComparator(String comparator) {
        Matcher cm = COMPARATOR.matcher(comparator);
        if (comparator.isEmpty() || !cm.matches()) {
            throw new IllegalArgumentException("invalid version requirement: '" + text + "'");
        }
        Op op = switch (cm.group(1) == null ? "^" : cm.group(1)) {
            case "=" -> Op.EQ;
            case ">" -> Op.GT;
            case ">=" -> Op.GE;
            case "<" -> Op.LT;
            case "<=" -> Op.LE;
            case "~" -> Op.TILDE;
            default -> Op.CARET;
        };
        Matcher m = PARTIAL.matcher(cm.group(2).trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid version requirement: '" + text + "'");
        }
        Long major = number(m.group(1));
        Long minor = major == null ? null : number(m.group(2));
        Long patch = minor == null ? null : number(m.group(3));
        List<String> pre = patch != null && m.group(4) != null ? List.of(m.group(4).split("\\.")) : List.of();

        if (major == null) {
            return; // "*" matches everything (pre-releases still excluded)
        }
        SemVer lower = new SemVer(major, minor == null ? 0 : minor, patch == null ? 0 : patch, pre);
        if (!pre.isEmpty()) {
            prereleaseAnchors.add(lower);
        }
        SemVer nextMajor = SemVer.of(major + 1, 0, 0);
        SemVer nextMinor = minor == null ? nextMajor : SemVer.of(major, minor + 1, 0);

        switch (op) {
            case EQ -> {
                if (patch != null) {
                    bounds.add(new Bound(Op.EQ, lower));
                } else {
                    bounds.add(new Bound(Op.GE, lower));
                    bounds.add(new Bound(Op.LT, nextMinor));
                }
            }
            case GT -> bounds.add(patch != null ? new Bound(Op.GT, lower) : new Bound(Op.GE, nextMinor));
            case GE -> bounds.add(new Bound(Op.GE, lower));
            case LT -> bounds.add(new Bound(Op.LT, lower));
            case LE -> bounds.add(patch != null ? new Bound(Op.LE, lower) : new Bound(Op.LT, nextMinor));
            case TILDE -> {
                bounds.add(new Bound(Op.GE, lower));
                bounds.add(new Bound(Op.LT, nextMinor));
            }
            case CARET -> {
                bounds.add(new Bound(Op.GE, lower));
                SemVer upper;
                if (major > 0 || minor == null) {
                    upper = nextMajor;
                } else if (minor > 0 || patch == null) {
                    upper = SemVer.of(0, minor + 1, 0);
                } else {
                    upper = SemVer.of(0, 0, patch + 1);
                }
                bounds.add(new Bound(Op.LT, upper));
            }
        }
    }

    private static Long number(String s) {
        return s == null || s.equals("*") || s.equalsIgnoreCase("x") ? null : Long.parseLong(s);
    }

    @Override
    public String toString() {
        return text;
    }
}
