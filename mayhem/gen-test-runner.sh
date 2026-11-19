#!/bin/sh
# Out-of-tree wrapper for upstream's util/generate-test-runner.pl, which opens the test sources by
# the relative paths make passes it and so only works in-tree. make runs this from
# $GUAC_TEST_BUILD/<dir>; the sources live in $SRC/<dir>.
rel="${PWD#"$GUAC_TEST_BUILD"/}"
cd "$SRC/$rel" && exec perl "$SRC/util/generate-test-runner.pl" "$@"
