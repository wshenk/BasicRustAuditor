package io.github.wshenk.rustauditor.toml;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small TOML reader covering what {@code Cargo.lock} files and RustSec advisory front matter use:
 * tables, arrays of tables, dotted and quoted keys, basic/literal/multi-line strings, arrays,
 * inline tables, booleans and numbers. Dates and other unrecognised bare values are returned as strings.
 *
 * <p>Tables are {@code Map<String, Object>}, arrays are {@code List<Object>}, and scalars are
 * {@link String}, {@link Long}, {@link Double} or {@link Boolean}.
 */
public final class MiniToml {

    private final String src;
    private int pos;

    private MiniToml(String src) {
        this.src = src;
    }

    /** Parses a TOML document into nested maps and lists. */
    public static Map<String, Object> parse(String text) {
        return new MiniToml(text).document();
    }

    // ---- typed accessors -------------------------------------------------------------------

    /** Returns the string at {@code key}, or {@code null} if absent or not a string. */
    public static String getString(Map<String, Object> table, String key) {
        return table != null && table.get(key) instanceof String s ? s : null;
    }

    /** Returns the strings in the array at {@code key}; non-string elements are ignored. */
    public static List<String> getStringList(Map<String, Object> table, String key) {
        List<String> out = new ArrayList<>();
        if (table != null && table.get(key) instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof String s) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    /** Returns the sub-table at {@code key}, or {@code null}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getTable(Map<String, Object> table, String key) {
        return table != null && table.get(key) instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    /** Returns the array of tables at {@code key} (e.g. {@code [[package]]}), or an empty list. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> getTableList(Map<String, Object> table, String key) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (table != null && table.get(key) instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> m) {
                    out.add((Map<String, Object>) m);
                }
            }
        }
        return out;
    }

    // ---- document structure ----------------------------------------------------------------

    private Map<String, Object> document() {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> current = root;
        while (true) {
            skipBlank();
            if (eof()) {
                return root;
            }
            if (peek() == '[') {
                boolean arrayTable = pos + 1 < src.length() && src.charAt(pos + 1) == '[';
                pos += arrayTable ? 2 : 1;
                List<String> keys = keyPath();
                expect(']');
                if (arrayTable) {
                    expect(']');
                    current = appendArrayTable(root, keys);
                } else {
                    current = table(root, keys);
                }
            } else {
                List<String> keys = keyPath();
                expect('=');
                skipSpaces();
                assign(current, keys, value());
            }
            endOfLine();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> table(Map<String, Object> start, List<String> keys) {
        Map<String, Object> m = start;
        for (String k : keys) {
            Object o = m.get(k);
            if (o == null) {
                Map<String, Object> created = new LinkedHashMap<>();
                m.put(k, created);
                m = created;
            } else if (o instanceof Map<?, ?> existing) {
                m = (Map<String, Object>) existing;
            } else if (o instanceof List<?> list && !list.isEmpty() && list.get(list.size() - 1) instanceof Map<?, ?> last) {
                m = (Map<String, Object>) last;
            } else {
                throw error("key '" + k + "' is already defined as a value");
            }
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> appendArrayTable(Map<String, Object> root, List<String> keys) {
        Map<String, Object> parent = table(root, keys.subList(0, keys.size() - 1));
        String last = keys.get(keys.size() - 1);
        Object o = parent.get(last);
        List<Object> list;
        if (o == null) {
            list = new ArrayList<>();
            parent.put(last, list);
        } else if (o instanceof List<?> existing) {
            list = (List<Object>) existing;
        } else {
            throw error("key '" + last + "' is not an array of tables");
        }
        Map<String, Object> created = new LinkedHashMap<>();
        list.add(created);
        return created;
    }

    private void assign(Map<String, Object> current, List<String> keys, Object value) {
        Map<String, Object> parent = table(current, keys.subList(0, keys.size() - 1));
        String last = keys.get(keys.size() - 1);
        if (parent.containsKey(last)) {
            throw error("duplicate key '" + last + "'");
        }
        parent.put(last, value);
    }

    private List<String> keyPath() {
        List<String> keys = new ArrayList<>();
        while (true) {
            skipSpaces();
            keys.add(key());
            skipSpaces();
            if (!eof() && peek() == '.') {
                pos++;
                continue;
            }
            return keys;
        }
    }

    private String key() {
        if (eof()) {
            throw error("expected a key");
        }
        char c = peek();
        if (c == '"') {
            return basicString();
        }
        if (c == '\'') {
            return literalString();
        }
        int start = pos;
        while (!eof() && (Character.isLetterOrDigit(peek()) || peek() == '_' || peek() == '-')) {
            pos++;
        }
        if (start == pos) {
            throw error("expected a key but found '" + c + "'");
        }
        return src.substring(start, pos);
    }

    // ---- values ----------------------------------------------------------------------------

    private Object value() {
        if (eof()) {
            throw error("expected a value");
        }
        return switch (peek()) {
            case '"' -> src.startsWith("\"\"\"", pos) ? multiLineBasicString() : basicString();
            case '\'' -> src.startsWith("'''", pos) ? multiLineLiteralString() : literalString();
            case '[' -> array();
            case '{' -> inlineTable();
            default -> scalar();
        };
    }

    private List<Object> array() {
        pos++; // [
        List<Object> list = new ArrayList<>();
        while (true) {
            skipBlank();
            if (eof()) {
                throw error("unterminated array");
            }
            if (peek() == ']') {
                pos++;
                return list;
            }
            list.add(value());
            skipBlank();
            if (!eof() && peek() == ',') {
                pos++;
                continue;
            }
            expect(']');
            return list;
        }
    }

    private Map<String, Object> inlineTable() {
        pos++; // {
        Map<String, Object> map = new LinkedHashMap<>();
        skipSpaces();
        if (!eof() && peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            List<String> keys = keyPath();
            expect('=');
            skipSpaces();
            assign(map, keys, value());
            skipSpaces();
            if (!eof() && peek() == ',') {
                pos++;
                continue;
            }
            expect('}');
            return map;
        }
    }

    private Object scalar() {
        int start = pos;
        while (!eof() && " \t\r\n,]}#".indexOf(peek()) < 0) {
            pos++;
        }
        String token = src.substring(start, pos);
        if (token.isEmpty()) {
            throw error("expected a value");
        }
        if (token.equals("true") || token.equals("false")) {
            return Boolean.parseBoolean(token);
        }
        String numeric = token.replace("_", "");
        try {
            return Long.parseLong(numeric);
        } catch (NumberFormatException ignored) {
            // not an integer
        }
        try {
            return Double.parseDouble(numeric);
        } catch (NumberFormatException ignored) {
            // dates, times and anything else stay as raw strings
        }
        return token;
    }

    private String basicString() {
        pos++; // "
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (eof() || peek() == '\n') {
                throw error("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                escape(sb);
            } else {
                sb.append(c);
            }
        }
    }

    private String multiLineBasicString() {
        pos += 3;
        skipNewline();
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (eof()) {
                throw error("unterminated multi-line string");
            }
            if (src.startsWith("\"\"\"", pos)) {
                pos += 3;
                // Up to two additional quotes directly before the delimiter belong to the content.
                for (int i = 0; i < 2 && !eof() && peek() == '"'; i++) {
                    sb.append('"');
                    pos++;
                }
                return sb.toString();
            }
            char c = src.charAt(pos++);
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            int p = pos;
            while (p < src.length() && (src.charAt(p) == ' ' || src.charAt(p) == '\t')) {
                p++;
            }
            if (p < src.length() && (src.charAt(p) == '\n' || src.charAt(p) == '\r')) {
                // Line-ending backslash: trim all whitespace up to the next non-blank character.
                pos = p;
                while (!eof() && Character.isWhitespace(peek())) {
                    pos++;
                }
            } else {
                escape(sb);
            }
        }
    }

    private String literalString() {
        pos++; // '
        int end = src.indexOf('\'', pos);
        int newline = src.indexOf('\n', pos);
        if (end < 0 || (newline >= 0 && newline < end)) {
            throw error("unterminated literal string");
        }
        String s = src.substring(pos, end);
        pos = end + 1;
        return s;
    }

    private String multiLineLiteralString() {
        pos += 3;
        skipNewline();
        int end = src.indexOf("'''", pos);
        if (end < 0) {
            throw error("unterminated multi-line literal string");
        }
        String s = src.substring(pos, end);
        pos = end + 3;
        return s;
    }

    private void escape(StringBuilder sb) {
        if (eof()) {
            throw error("unterminated escape sequence");
        }
        char e = src.charAt(pos++);
        switch (e) {
            case 'b' -> sb.append('\b');
            case 't' -> sb.append('\t');
            case 'n' -> sb.append('\n');
            case 'f' -> sb.append('\f');
            case 'r' -> sb.append('\r');
            case 'e' -> sb.append('\u001b');
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case 'u' -> sb.appendCodePoint(hex(4));
            case 'U' -> sb.appendCodePoint(hex(8));
            default -> throw error("invalid escape sequence '\\" + e + "'");
        }
    }

    private int hex(int digits) {
        if (pos + digits > src.length()) {
            throw error("truncated unicode escape");
        }
        try {
            int cp = Integer.parseInt(src.substring(pos, pos + digits), 16);
            pos += digits;
            return cp;
        } catch (NumberFormatException e) {
            throw error("invalid unicode escape");
        }
    }

    // ---- lexical helpers -------------------------------------------------------------------

    private boolean eof() {
        return pos >= src.length();
    }

    private char peek() {
        return src.charAt(pos);
    }

    private void skipSpaces() {
        while (!eof() && (peek() == ' ' || peek() == '\t')) {
            pos++;
        }
    }

    /** Skips whitespace, newlines and comments. */
    private void skipBlank() {
        while (!eof()) {
            char c = peek();
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else if (c == '#') {
                skipComment();
            } else {
                return;
            }
        }
    }

    private void skipComment() {
        while (!eof() && peek() != '\n') {
            pos++;
        }
    }

    private void skipNewline() {
        if (src.startsWith("\r\n", pos)) {
            pos += 2;
        } else if (!eof() && peek() == '\n') {
            pos++;
        }
    }

    private void endOfLine() {
        skipSpaces();
        if (!eof() && peek() == '#') {
            skipComment();
        }
        if (eof()) {
            return;
        }
        if (peek() == '\r') {
            pos++;
        }
        if (eof() || peek() != '\n') {
            throw error("expected end of line");
        }
        pos++;
    }

    private void expect(char c) {
        skipSpaces();
        if (eof() || peek() != c) {
            throw error("expected '" + c + "'");
        }
        pos++;
    }

    private TomlException error(String message) {
        int line = 1;
        for (int i = 0; i < Math.min(pos, src.length()); i++) {
            if (src.charAt(i) == '\n') {
                line++;
            }
        }
        return new TomlException(message, line);
    }
}
