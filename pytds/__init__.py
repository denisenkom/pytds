from .dbapi import *
from .tds import *
from .dbapi import __version__

def ver_to_int(ver):
    maj, minor, rev = ver.split('.')
    return (int(maj) << 24) + (int(minor) << 16) + (int(rev) << 8)

intversion = ver_to_int(__version__)
