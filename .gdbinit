# Add this line to ~/.gdbinit:
# add-auto-load-safe-path ~/path/to/owl-sw
#
# Alternatively whitelist the path on the GDB command line:
# $ gdb -iex "set auto-load safe-path ~/path/to/owl-sw" ...

# Alternatively source the file from within GDB:
# $ gdb -args ./dump trace.bin
# (gdb) source ./gdbinit

source ./.gdbinit.py
