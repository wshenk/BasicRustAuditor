package io.github.wshenk.rustauditor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

class CvssTest {

    @ParameterizedTest
    @CsvSource({
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8, critical",
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, 6.2, medium",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, 10.0, critical",
            "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N, 4.4, medium",
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N, 1.6, low",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 0.0, none",
    })
    void scoresV3Vectors(String vector, double score, String severity) {
        assertEquals(score, Cvss.baseScore(vector).orElseThrow());
        assertEquals(severity, Cvss.severity(score));
    }

    @Test
    void ignoresUnsupportedVectors() {
        assertTrue(Cvss.baseScore(null).isEmpty());
        assertTrue(Cvss.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").isEmpty());
        assertTrue(Cvss.baseScore("CVSS:3.1/AV:N").isEmpty());
    }
}
