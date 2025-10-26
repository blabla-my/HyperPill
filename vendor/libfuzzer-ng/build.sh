#!/bin/sh
LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang}"
OPT_LEVEL="-O2"
if [ "$DEBUG" = "1" ]; then
  OPT_LEVEL="-O0"
fi

for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX -g $OPT_LEVEL -fno-omit-frame-pointer -std=c++11 -fPIE $f -c &
done
wait
rm -f libFuzzer.a
ar ru libFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o
