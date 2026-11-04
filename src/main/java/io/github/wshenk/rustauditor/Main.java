package io.github.wshenk.rustauditor;

import io.github.wshenk.rustauditor.toml.TomlException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/** Command-line entry point. */
public final class Main {

    /** Exit code when the audit found nothing that fails the build. */
    public static final int OK = 0;
    /** Exit code when vulnerabilities (or, with {@code --deny-warnings}, warnings) were found. */
    public static final int FINDINGS = 1;
    /** Exit code for usage errors and I/O failures. */
    public static final int ERROR = 2;

    private static final String USAGE = """
            Usage: basic-rust-auditor [options] [PATH]

            Audits a Rust project's Cargo.lock against the RustSec advisory database.

            PATH                  a Cargo.lock file, or a directory containing one (default: .)

            Options:
              --db DIR            advisory-db checkout to use
                                  (default: ~/.cache/basic-rust-auditor/advisory-db)
              --db-url URL        git URL to clone the advisory-db from
                                  (default: %s)
              --no-fetch          don't clone or update the advisory-db; use it as-is
              --format FORMAT     text (default) or json
              --ignore ID         ignore an advisory by RUSTSEC id or alias (repeatable)
              --deny-warnings     exit with status 1 on warnings as well as vulnerabilities
              -h, --help          show this help
              --version           show the version

            Exit status: 0 = clean, 1 = findings, 2 = error
            """.formatted(AdvisoryDatabase.DEFAULT_URL);

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Runs the CLI and returns its exit code (separated from {@link #main} for testing). */
    public static int run(String[] args, PrintStream out, PrintStream err) {
        Path target = Path.of(".");
        Path db = Path.of(System.getProperty("user.home"), ".cache", "basic-rust-auditor", "advisory-db");
        String dbUrl = AdvisoryDatabase.DEFAULT_URL;
        boolean fetch = true;
        boolean json = false;
        boolean denyWarnings = false;
        Set<String> ignore = new LinkedHashSet<>();
        boolean targetSet = false;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            try {
                switch (arg) {
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return OK;
                    }
                    case "--version" -> {
                        String v = Main.class.getPackage().getImplementationVersion();
                        out.println("basic-rust-auditor " + (v == null ? "dev" : v));
                        return OK;
                    }
                    case "--db" -> db = Path.of(value(args, ++i, arg));
                    case "--db-url" -> dbUrl = value(args, ++i, arg);
                    case "--no-fetch" -> fetch = false;
                    case "--deny-warnings" -> denyWarnings = true;
                    case "--ignore" -> ignore.add(value(args, ++i, arg));
                    case "--format" -> {
                        String format = value(args, ++i, arg);
                        if (!format.equals("text") && !format.equals("json")) {
                            throw new IllegalArgumentException("--format must be 'text' or 'json'");
                        }
                        json = format.equals("json");
                    }
                    default -> {
                        if (arg.startsWith("-") || targetSet) {
                            throw new IllegalArgumentException("unexpected argument: " + arg);
                        }
                        target = Path.of(arg);
                        targetSet = true;
                    }
                }
            } catch (IllegalArgumentException e) {
                err.println("error: " + e.getMessage());
                err.println("Run with --help for usage.");
                return ERROR;
            }
        }

        Path lockfile = Files.isDirectory(target) ? target.resolve("Cargo.lock") : target;
        if (!Files.isRegularFile(lockfile)) {
            err.println("error: " + lockfile + " not found (run `cargo generate-lockfile` first?)");
            return ERROR;
        }

        try {
            CargoLock lock = CargoLock.read(lockfile);
            if (fetch) {
                try {
                    AdvisoryDatabase.fetch(db, dbUrl, err);
                } catch (IOException e) {
                    if (!Files.isDirectory(db.resolve("crates"))) {
                        throw e;
                    }
                    err.println("warning: could not update advisory database, using existing copy: " + e.getMessage());
                }
            }
            AdvisoryDatabase database = AdvisoryDatabase.load(db);
            for (String problem : database.loadErrors()) {
                err.println("warning: skipped unparseable advisory " + problem);
            }

            AuditReport report = new Auditor(database, ignore).audit(lock, lockfile.toString());
            out.print(json ? ReportRenderer.json(report) : ReportRenderer.text(report));

            boolean fail = !report.vulnerabilities().isEmpty() || (denyWarnings && !report.warnings().isEmpty());
            return fail ? FINDINGS : OK;
        } catch (TomlException e) {
            err.println("error: could not parse " + lockfile + ": " + e.getMessage());
            return ERROR;
        } catch (IOException | RuntimeException e) {
            err.println("error: " + e.getMessage());
            return ERROR;
        }
    }

    private static String value(String[] args, int i, String option) {
        if (i >= args.length) {
            throw new IllegalArgumentException(option + " requires a value");
        }
        return args[i];
    }
}
