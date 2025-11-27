#!/bin/bash

TAG='_libparse_build'

docker build -t libparse:$TAG -f $PGAUZE_ROOT_LOCATION/poc_gauze_lib/Dockerfile $PMACCT_ROOT_LOCATION || exit $?

CONTAINER_ID=$(docker create libparse:$TAG)

docker cp $CONTAINER_ID:/usr/pmacct-gauze/poc_gauze_lib/src/.libs/libparse.so libparse.so

mv libparse.so $PMACCT_ROOT_LOCATION/libparse.so

$PMACCT_ROOT_LOCATION/test-framework/tools/pmacct_build/build_docker_images.sh -p libparse.so