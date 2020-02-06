#!/bin/bash
binary=$1
expected=$2
echo "Testing $binary"
{ ./$binary; } >&/dev/null
if [ $? = $expected ]; then echo "$binary expected return status $expected"; else echo "Failed! $binary"; exit 1; fi
