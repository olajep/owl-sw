# Owl software

## dump

```sh
$ make dump
$ gunzip example.bin.gz
$ ./dump -f flame example.bin > example.txt
$ flamegraph.pl --flamechart --width 4800 < example.txt > example.svg
```

Open SVG file in a browser.
