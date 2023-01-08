# ludvig

Secret scanner

Named after Kjell Aukrust's character Ludvig who thinks everything is dangerous and is scared of the dark during the day.

Very much Work In Progress - won't give you much at this point :P

Requires:

- `yara`

## Usage

The general usage of the tool is: `python -m ludvig [--deobfuscated] [--custom-rules <PATH>] <scan type> <args>`

`--deobfuscated` will reveal any secrets found, default is to obfuscate the secret

`--custom-rules <PATH>` lets you specify your own YARA rules (loads all `.yar` files under the specified `<PATH>`)

### Container scan

Scan a container: `python -m ludvig image <image>`

### Filesystem scan

Scan the filesystem: `python -m ludvig fs <path>`

## Docker

Build: `docker build -t ludvig:latest .`

Run: `docker run -t -v /var/run/docker.sock:/var/run/docker.sock ludvig:latest sample:latest`

NOTE: Requires mounting the Docker socket to be able to read Docker images
