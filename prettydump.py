#!/usr/bin/python3

import sys
import re
from os import *
import subprocess
from subprocess import *

def offs2vaddr(binary, offs):
    path = "/home/olaj/riscv/sysroot" + binary
    with subprocess.Popen(["./offs2vaddr", path, hex(offs)], stdout=PIPE) as proc:
        vaddr = proc.stdout.read().rstrip().decode('UTF-8')
    return int(vaddr, 16)

def addr2line(binary, vaddr):
    path = "/home/olaj/riscv/sysroot" + binary
    cmdline = ["riscv64-unknown-linux-gnu-addr2line", "-f", "-e", path, hex(vaddr)]
    with subprocess.Popen(cmdline, stdout=PIPE) as proc:
        function = proc.stdout.readline().rstrip().decode('UTF-8')
        srcfile = proc.stdout.readline().rstrip().decode('UTF-8')
    return function, srcfile

def prettify(string):
    match = re.match("^([^+]*)[+](.*)$", string)
    if not match:
        return string
    else:
        (binary, offs_str) = (match[1], match[2])
    try:
        offs = int(offs_str, 10)
    except ValueError:
        offs = int(offs_str, 16)
    # HACK: to detect supervisor / Linux Kernel mode
    if (offs >= 0xe00000000):
        vaddr = offs
    else:
        vaddr = offs2vaddr(binary, offs)

    function, srcfile = addr2line(binary, vaddr)

    srcfile = srcfile.split(" ")[0]
    return function + "@" + path.basename(binary) + ":" + path.basename(srcfile)

def parse(line):
    match = re.match("^(.*file=\[)([^\]]*)(].*)$", line)
    if not match:
        match = re.match("^(.*file://)([^; ]*)(.*)$", line)

    if not match:
        print(line)
    else:
        print(match[1], prettify(match[2]), match[3], sep='')

try:
    for line in sys.stdin:
        parse(line.rstrip())
except BrokenPipeError:
    pass
