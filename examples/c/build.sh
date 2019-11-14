#!/usr/bin/env bash
set -e

#
# Copyright 2019 ForgeRock AS
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

#
# Build the Simple Client examples
#

# Change this path to your local C compiler
export CC=/usr/bin/x86_64-linux-gnu-gcc

# name of example
# assumes source code is in ./src/${ex}/${ex}.c
ex=$1

libs="-liecclient -lsodium -lzmq -lmosquitto"
lib_dir=$(pwd)/../lib/
dist_dir=$(pwd)/dist/
inc_dir=$(pwd)/../include/

mkdir -p ${dist_dir}/${ex}
(${CC} src/${ex}/${ex}.c -o ${dist_dir}/${ex}/${ex} -I${inc_dir} -L${lib_dir} ${libs})
