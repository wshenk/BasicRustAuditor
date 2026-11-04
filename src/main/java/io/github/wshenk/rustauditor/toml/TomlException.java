package io.github.wshenk.rustauditor.toml;

/** Thrown when a TOML document cannot be parsed. */
public final class TomlException extends RuntimeException {

    private final int line;

    public TomlException(String message, int line) {
        super("line " + line + ": " + message);
        this.line = line;
    }

    /** The 1-based line on which the error was detected. */
    public int line() {
        return line;
    }
}
