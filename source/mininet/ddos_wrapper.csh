#!/bin/csh
# Wrapper to run POSIX ddos script when invoked with csh/tcsh.
set script_dir = `dirname "$0"`
set candidate1 = "$script_dir/ddos.csh"
set candidate2 = "$script_dir/ddos_no_flood.csh"

if ( -f "$candidate1" ) then
  set real = "$candidate1"
else if ( -f "$candidate2" ) then
  set real = "$candidate2"
else
  echo "Error: expected POSIX script not found at $candidate1 or $candidate2"
  exit 1
endif

exec /bin/sh "$real" "$@"