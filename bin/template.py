#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import io
from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF(args.EXE or './BINARY_NAME')

def start_local(args, argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(host, port, argv=[], *a, **kw):
    return remote(host, port)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

parser = argparse.ArgumentParser(description='Exploit script')
parser.add_argument('mode', choices=['local', 'remote'], help='Mode: local or remote')
parser.add_argument('--GDB', action='store_true', help='Enable GDB debugging')
parser.add_argument('host', nargs='?', default='localhost', help='Remote host')
parser.add_argument('port', nargs='?', type=int, default=1337, help='Remote port')
args = parser.parse_args()

if args.mode == 'local':
    start_func = lambda: start_local(args)
else:
    start_func = lambda: start_remote(args.host, args.port)

io = start_func() 
###################
#EXPLOIT GOES HERE#
###################
io.interactive()

