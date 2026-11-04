package io.github.wshenk.rustauditor;

import java.util.HashMap;
import java.util.Map;
import java.util.OptionalDouble;

/** Computes CVSS v3.0/v3.1 base scores from vector strings. CVSS v4 vectors are not scored. */
public final class Cvss {

    private Cvss() {
    }

    /** Returns the base score of a {@code CVSS:3.x/...} vector, or empty if it can't be scored. */
    public static OptionalDouble baseScore(String vector) {
        if (vector == null || !(vector.startsWith("CVSS:3.0/") || vector.startsWith("CVSS:3.1/"))) {
            return OptionalDouble.empty();
        }
        Map<String, String> m = new HashMap<>();
        for (String part : vector.substring("CVSS:3.x/".length()).split("/")) {
            String[] kv = part.split(":", 2);
            if (kv.length == 2) {
                m.put(kv[0], kv[1]);
            }
        }
        try {
            boolean changed = "C".equals(require(m, "S"));
            double av = switch (require(m, "AV")) {
                case "N" -> 0.85;
                case "A" -> 0.62;
                case "L" -> 0.55;
                case "P" -> 0.2;
                default -> throw new IllegalArgumentException();
            };
            double ac = switch (require(m, "AC")) {
                case "L" -> 0.77;
                case "H" -> 0.44;
                default -> throw new IllegalArgumentException();
            };
            double pr = switch (require(m, "PR")) {
                case "N" -> 0.85;
                case "L" -> changed ? 0.68 : 0.62;
                case "H" -> changed ? 0.5 : 0.27;
                default -> throw new IllegalArgumentException();
            };
            double ui = switch (require(m, "UI")) {
                case "N" -> 0.85;
                case "R" -> 0.62;
                default -> throw new IllegalArgumentException();
            };
            double iss = 1 - (1 - cia(require(m, "C"))) * (1 - cia(require(m, "I"))) * (1 - cia(require(m, "A")));
            double impact = changed
                    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
                    : 6.42 * iss;
            if (impact <= 0) {
                return OptionalDouble.of(0.0);
            }
            double exploitability = 8.22 * av * ac * pr * ui;
            double raw = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
            return OptionalDouble.of(roundUp(Math.min(raw, 10.0)));
        } catch (IllegalArgumentException e) {
            return OptionalDouble.empty();
        }
    }

    /** Maps a CVSS score to its qualitative rating. */
    public static String severity(double score) {
        if (score == 0.0) {
            return "none";
        } else if (score < 4.0) {
            return "low";
        } else if (score < 7.0) {
            return "medium";
        } else if (score < 9.0) {
            return "high";
        }
        return "critical";
    }

    private static String require(Map<String, String> m, String key) {
        String v = m.get(key);
        if (v == null) {
            throw new IllegalArgumentException(key);
        }
        return v;
    }

    private static double cia(String v) {
        return switch (v) {
            case "H" -> 0.56;
            case "L" -> 0.22;
            case "N" -> 0.0;
            default -> throw new IllegalArgumentException();
        };
    }

    /** The CVSS v3.1 "Roundup" function (avoids floating point surprises). */
    private static double roundUp(double value) {
        long i = Math.round(value * 100_000);
        if (i % 10_000 == 0) {
            return i / 100_000.0;
        }
        return (Math.floor(i / 10_000.0) + 1) / 10.0;
    }
}
