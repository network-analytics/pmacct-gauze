#!/bin/bash

docker build --build-arg NUM_WORKERS=$(nproc) --target build-stage -t pmacct-build-image -f $PMACCT_ROOT_LOCATION/docker/base/Dockerfile $PMACCT_ROOT_LOCATION || exit $?

TAG='_libparse_build'

docker build --progress=plain -t libparse:$TAG -f $PGAUZE_ROOT_LOCATION/poc_gauze_lib/Dockerfile $PGAUZE_ROOT_LOCATION || exit $?

CONTAINER_ID=$(docker create libparse:$TAG)

docker cp $CONTAINER_ID:/usr/pmacct-gauze/poc_gauze_lib/src/.libs/libparse.so libparse.so

docker cp $CONTAINER_ID:/tmp/pmacct/src/buildflags.txt buildflags.txt

docker cp $CONTAINER_ID:/tmp/pmacct/Makefile inside_Makefile

docker cp $CONTAINER_ID:/usr/local/lib/pkgconfig/pmacct.pc pmacct.pc

mv libparse.so $PMACCT_ROOT_LOCATION/test-framework/libparse.so

$PMACCT_ROOT_LOCATION/test-framework/tools/pmacct_build/build_docker_images.sh