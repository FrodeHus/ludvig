# Ludvig

[![Ludvig scan](https://github.com/FrodeHus/ludvig/actions/workflows/main.yml/badge.svg)](https://github.com/FrodeHus/ludvig/actions/workflows/main.yml)

> Want to use Ludvig with your CI pipeline? Mosey on over to the [Ludvig Action](https://github.com/marketplace/actions/ludvig-security-scanner) :)

Security scanner

Named after Kjell Aukrust's character Ludvig who thinks everything is dangerous and is scared of the dark during the day.

Why yet another scanner?

Mostly because I thought it was a fun way to use YARA rules for something in addition to malware hunting and to learn how these kind of tools are made.

## Usage

The general usage of the tool can be found by running `python -m ludvig --help`

### Container scan

Scan container: `python -m ludvig image scan --repository <repository>`

```
ludvig image scan --help

Command
    ludvig image scan : Scans a container image.

Arguments
    --repository [Required] : Container image to scan (ex: myimage:1.1).
    --custom-rules          : Path to any custom YARA rules (need to have .yar extension).
    --deobfuscated          : Returns any secrets found in plaintext. Defaults to False.
    --output-sarif          : Generates SARIF report if filename is specified.
    --severity-level        : Set severity level for reporting.  Allowed values: CRITICAL, HIGH,
                              LOW, MEDIUM, UNKNOWN.  Default: MEDIUM.
```

### Filesystem scan

Scan the filesystem: `python -m ludvig fs scan --path <path>`

```
ludvig fs scan --help

Command
    ludvig fs scan : Scans a filesystem path.

Arguments
    --path  [Required] : Path to scan.
    --custom-rules     : Path to any custom YARA rules (need to have .yar extension).
    --deobfuscated     : Returns any secrets found in plaintext. Defaults to False.
    --output-sarif     : Generates SARIF report if filename is specified.
    --severity-level   : Set severity level for reporting.  Allowed values: CRITICAL, HIGH, LOW,
                         MEDIUM, UNKNOWN.  Default: MEDIUM.
```

### Adding files/directories to ignore list

Create a `.ludvignore` file such as:

```
*.yar
debug/
```
