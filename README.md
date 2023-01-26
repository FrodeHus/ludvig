# Ludvig

[![Ludvig scan](https://github.com/FrodeHus/ludvig/actions/workflows/ludvig.yml/badge.svg)](https://github.com/FrodeHus/ludvig/actions/workflows/ludvig.yml)

Secret scanner

Named after Kjell Aukrust's character Ludvig who thinks everything is dangerous and is scared of the dark during the day.

Very much Work In Progress

## GitHub Action usage

```yaml
name: "Ludvig test"
on:
  workflow_dispatch:

jobs:
  ludvig:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
      - name: Run Ludvig
        uses: FrodeHus/ludvig@v0.2.5
        with:
          path: "<path to scan>"
          customRulesPath: "<path to custom YARA rules - optional>"
          level: "<UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL - optional (default: MEDIUM)>"
          sarifFileName: "SARIF file name (enables SARIF generation)"
```

## Adding files/directories to ignore list

Create a `.ludvignore` file such as:

```
*.yar
debug/
```

## CLI Usage

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
