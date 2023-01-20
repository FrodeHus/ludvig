# Ludvig

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
      uses: FrodeHus/ludvig@v0.1.3
      with:
        path: 
          '<path to scan>'
        customRulesPath:
          '<path to custom YARA rules - optional>'
        level:
          '<UNKNOWN,TRIVIAL,LOW,MEDIUM,HIGH,CRITICAL - optional (default: MEDIUM)>'
```



## CLI Usage

The general usage of the tool is: `python -m ludvig [--deobfuscated] [--custom-rules <PATH>] <scan type> <args>`

`--deobfuscated` will reveal any secrets found, default is to obfuscate the secret

`--custom-rules <PATH>` lets you specify your own YARA rules (loads all `.yar` files under the specified `<PATH>`)

`--level <LEVEL>` Only report findings above the given level (UNKNOWN,TRIVIAL,LOW,MEDIUM,HIGH,CRITICAL - default: MEDIUM)

### Container scan

Scan a container: `python -m ludvig image <image>`

### Filesystem scan

Scan the filesystem: `python -m ludvig fs <path>`


