#!/bin/bash

docker build -t crypto-mediatek-test .
docker run --name=crypto-mediatek-test crypto-mediatek-test true
docker cp crypto-mediatek-test:/code/target/armv7-unknown-linux-musleabihf/release/examples/test .
docker rm -f crypto-mediatek-test

echo "Compiled: ./test"