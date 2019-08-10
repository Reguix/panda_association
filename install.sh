#!/bin/bash
# install panda
sudo add-apt-repository ppa:phulin/panda
sudo apt-get update
sudo apt-get -y install python-pip git protobuf-compiler protobuf-c-compiler \
  libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev \
  libcapstone-dev libdwarf-dev python-pycparser llvm-3.3 clang-3.3 libc++-dev \
  bison flex wireshark-dev

mkdir -p build-panda && cd build-panda
../panda/build.sh
cd ..

# install jsoncpp
sudo apt-get -y install scons
tar -zxvf jsoncpp-svn-release-0.5.0.tar.gz
cd jsoncpp-svn-release-0.5.0
scons platform=linux-gcc
cd libs
gcc_version=$(ls)
cd $gcc_version
sudo cp "libjson_"$gcc_version"_libmt.a" /usr/lib/libjsoncpp.a
sudo cp "libjson_"$gcc_version"_libmt.so" /usr/lib/libjsoncpp.so
cd ../../include
sudo cp -r json/ /usr/include/
