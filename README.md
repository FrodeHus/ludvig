# ludvig

Container secret scanner

Named after Kjell Aukrust's character Ludvig who thinks everything is dangerous and is scared of the dark during the day.

Very much Work In Progress - won't give you much at this point :P

Requires:

- `yara`

## Docker

Build: `docker build -t ludvig:latest .`

Run: `docker run -t -v /var/run/docker.sock:/var/run/docker.sock ludvig:latest sample:latest`

NOTE: Requires mounting the Docker socket to be able to read Docker images
