# a pmacct custom parsing library

This is a C library acting as glue between pmacct-gauze and pmacct and meant to be used as a custom parsing library for pmacct.

# How to build :

- clone pmacct locally and install it (see [pmacct - Building](https://github.com/pmacct/pmacct?tab=readme-ov-file#building))
- clone the pmacct-gauze repository : `git clone https://github.com/mxyns/pmacct-gauze -b pmacct-gauze-rebased`
- install pmacct-gauze (see the repository's root README)
- in the `poc_gauze_lib` directory, build the library :
```bash
autoreconf -fi
./configure
PMACCT_INCLUDE_DIR="{path to pmacct root}/src" make
```
- after building the project, the library will be in `poc_gauze_lib/src/.libs/libparse.so`
- to use this library as a custom parsing lib for pmacct at runtime, refer to pmacct documentation (in `pmacct/src/custom_packet_parsing/README.md`)

# How to build the pmacct testing docker images :

A script is included to build the pmacct testing docker images with the library included : `poc_gauze_lib/docker_lib_build_script.sh`

To use it, you must have the environment variables `PMACCT_ROOT_LOCATION` and `PGAUZE_ROOT_LOCATION` set to the paths to the roots of your clones of both repositories (for example, `PMACCT_ROOT_LOCATION="/home/user/pmacct"` and `PGAUZE_ROOT_LOCATION="/home/user/pmacct-gauze"`)

Once these variables are set, you can run the script : `./docker_lib_build_script.sh`

The script does the following :
- builds a docker image of pmacct's `base` image up to the `build-stage` under the tag `pmacct-build-image`
- uses that image as a base for another image which copies the local pmacct-gauze repo and installs all necessary tools
- builds both pmacct-gauze and the library inside the image to have the same environment as the target
- starts a container to copy the custom parsing library out of it
- moves the parsing library to the root of the local pmacct repository
- builds the full pmacct testing docker images with the parsing library using `pmacct/test-framework/tools/pmacct_build/build_docker_images.sh`

Once the script has finished running, any test from pmacct's test-framework will use the images with the parsing library included at `/usr/local/lib/libparse.so`. Tests with the configuration option `custom_packet_parsing_lib:/usr/local/lib/libparse.so` will load the library.

