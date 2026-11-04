package io.github.wshenk.rustauditor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

class VersionReqTest {

    @ParameterizedTest(name = "\"{0}\" matches {1} = {2}")
    @CsvSource(delimiter = '|', value = {
            ">= 1.2.3          | 1.2.3        | true",
            ">= 1.2.3          | 1.2.2        | false",
            ">= 1.2.3, < 1.3.0 | 1.2.9        | true",
            ">= 1.2.3, < 1.3.0 | 1.3.0        | false",
            "< 0.2.23          | 0.2.22       | true",
            "> 1.2             | 1.2.9        | false",
            "> 1.2             | 1.3.0        | true",
            "<= 1.2            | 1.2.99       | true",
            "<= 1.2            | 1.3.0        | false",
            "=0.2.0            | 0.2.0        | true",
            "=0.2              | 0.2.7        | true",
            "=0.2              | 0.3.0        | false",
            "^1.2.3            | 1.9.0        | true",
            "^1.2.3            | 2.0.0        | false",
            "^0.2.3            | 0.2.9        | true",
            "^0.2.3            | 0.3.0        | false",
            "^0.0.3            | 0.0.4        | false",
            "^0.1              | 0.1.7        | true",
            "^0                | 0.9.9        | true",
            "^0                | 1.0.0        | false",
            "1.2.3             | 1.5.0        | true",
            "~1.2.3            | 1.2.9        | true",
            "~1.2.3            | 1.3.0        | false",
            "~1                | 1.9.0        | true",
            "0.1.*             | 0.1.5        | true",
            "0.1.*             | 0.2.0        | false",
            "*                 | 42.0.0       | true",
            ">= 1.0.0          | 1.1.0-alpha  | false",
            ">= 1.1.0-alpha    | 1.1.0-beta   | true",
            ">= 1.1.0-alpha    | 1.2.0-beta   | false",
            "< 2.0.0           | 2.0.0-rc.1   | false",
    })
    void matches(String req, String version, boolean expected) {
        assertEquals(expected, VersionReq.parse(req).matches(SemVer.parse(version)));
    }

    @Test
    void semverOrdering() {
        String[] ordered = {"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
                "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "10.0.0"};
        for (int i = 1; i < ordered.length; i++) {
            assertTrue(SemVer.parse(ordered[i - 1]).compareTo(SemVer.parse(ordered[i])) < 0,
                    ordered[i - 1] + " < " + ordered[i]);
        }
        assertEquals(0, SemVer.parse("1.0.0+build.5").compareTo(SemVer.parse("1.0.0")));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> VersionReq.parse(">= banana"));
        assertThrows(IllegalArgumentException.class, () -> VersionReq.parse(""));
        assertThrows(IllegalArgumentException.class, () -> SemVer.parse("1.2"));
        assertFalse(VersionReq.parse("=1.0.0").matches(SemVer.parse("1.0.1")));
    }
}
