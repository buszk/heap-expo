#!/bin/bash
binary=$1
expected=$2
echo "Testing $binary"
{ ./$binary; } >&/dev/null
ret=$?
if [ $ret = $expected ]; then echo "$binary expected return status $expected"; else echo "Failed! $binary. Expected $expected. Got $ret"; exit 1; fi
