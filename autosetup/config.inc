source "$PATHROOT/autosetup/targets/parsec/benchmarks.inc"       # BENCHMARKS_PARSEC
source "$PATHROOT/autosetup/targets/spec-cpu2006/benchmarks.inc" # BENCHMARKS_SPEC

: ${INSTANCES=heap-expo heap-expo-stats dangsan dangsan-stats baseline-lto}
: ${INSTANCESUFFIX=}
: ${JOBSMAX=16}
: ${TARGETS=spec-cpu2006}
: ${THREADCOUNTS:="1 2 4 8 16 32 64"}
