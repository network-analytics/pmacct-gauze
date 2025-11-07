#!/bin/bash

docker build --build-arg NUM_WORKERS=$(nproc) --target build-stage -t pmacct-build-image -f $PMACCT_ROOT_LOCATION/docker/base/Dockerfile $PMACCT_ROOT_LOCATION || exit $?

TAG='_libparse_build'

docker build -t libparse:$TAG -f $PGAUZE_ROOT_LOCATION/poc_gauze_lib/Dockerfile $PGAUZE_ROOT_LOCATION || exit $?