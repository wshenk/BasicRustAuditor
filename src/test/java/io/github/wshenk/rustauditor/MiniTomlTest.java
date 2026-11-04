package io.github.wshenk.rustauditor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.wshenk.rustauditor.toml.MiniToml;
import io.github.wshenk.rustauditor.toml.TomlException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MiniTomlTest {

    @Test
    void parsesTablesArraysAndStrings() {
        Map<String, Object> doc = MiniToml.parse("""
                # comment
                title = "a \\"quoted\\" \\u00e9" # trailing comment
                literal = 'C:\\path'
                n = 1_000
                f = 1.5
                yes = true
                date = 2020-01-31

                [advisory]
                list = [
                    "one", # comment inside array
                    "two",
                ]
                inline = { a = 1, b.c = "x" }

                [affected.functions]
                "time::at" = ["^0.1"]

                [[package]]
                name = "a"

                [[package]]
                name = "b"
                text = \"""
                first \\
                  second\"""
                """);
        assertEquals("a \"quoted\" é", doc.get("title"));
        assertEquals("C:\\path", doc.get("literal"));
        assertEquals(1000L, doc.get("n"));
        assertEquals(1.5, doc.get("f"));
        assertEquals(true, doc.get("yes"));
        assertEquals("2020-01-31", doc.get("date"));

        Map<String, Object> advisory = MiniToml.getTable(doc, "advisory");
        assertEquals(List.of("one", "two"), MiniToml.getStringList(advisory, "list"));
        assertEquals(Map.of("a", 1L, "b", Map.of("c", "x")), advisory.get("inline"));
        assertEquals(List.of("^0.1"),
                MiniToml.getStringList(MiniToml.getTable(MiniToml.getTable(doc, "affected"), "functions"), "time::at"));

        List<Map<String, Object>> packages = MiniToml.getTableList(doc, "package");
        assertEquals(2, packages.size());
        assertEquals("b", packages.get(1).get("name"));
        assertEquals("first second", packages.get(1).get("text"));
    }

    @Test
    void reportsLineOfErrors() {
        TomlException e = assertThrows(TomlException.class, () -> MiniToml.parse("a = 1\nb = \"unterminated\n"));
        assertEquals(2, e.line());
        assertThrows(TomlException.class, () -> MiniToml.parse("a = 1\na = 2\n"));
    }
}
