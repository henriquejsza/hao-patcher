#!/usr/bin/env python3
"""Build the host ObjC writer using CACHE_TOOLCHAIN."""
from dyld_rebuild.host_tools import objc

def build(out):
    binary = objc(out)
    return binary, {}
