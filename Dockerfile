FROM rust:1.38.0

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt-get install -y clang-format

RUN echo "Building for target armv7-linux-musleabihf"

ENV CONFIG_MAK 'CONFIG_MAK = COMMON_CONFIG += --disable-nls\nGCC_CONFIG += --enable-languages=c,c++\nGCC_CONFIG += --disable-libquadmath --disable-decimal-float\nGCC_CONFIG += --disable-multilib\nGCC_CONFIG += --disable-shared\nMUSL_CONFIG += CFLAGS="-O3" CXXFLAGS="-O3"\nGCC_CONFIG += --with-float=hard\nGCC_CONFIG += --with-arch=armv7-a\nGCC_CONFIG += --with-fpu=vfp3'

WORKDIR /build

ENV TARGET armv7-linux-musleabihf

RUN mkdir musl-output && git clone https://github.com/richfelker/musl-cross-make.git && \
    cd musl-cross-make && git checkout 629189831f61b73ba1053624eee12ff6a816438f && \
    echo ${CONFIG_MAK} > /build/musl-cross-make/config.mak && cat /build/musl-cross-make/config.mak && \
    make GNU_SITE=http://mirrors.kernel.org/gnu GCC_VER=8.3.0 MUSL_VER=1.1.22 && make install GCC_VER=8.3.0 MUSL_VER=1.1.22 && \
    mkdir -p /build/musl-output && mv /build/musl-cross-make/output/* /build/musl-output && rm -rf /build/musl-cross-make

ENV PATH /build/musl-output/bin/:$PATH
ENV ARCH_CFLAGS "-O3 -mfloat-abi=hard -march=armv7-a -mfpu=vfp3"

ENV CC_armv7_unknown_linux_musleabihf /build/musl-output/bin/armv7-linux-musleabihf-gcc
ENV AR_armv7_unknown_linux_musleabihf /build/musl-output/bin/armv7-linux-musleabihf-ar
ENV CXX_armv7_unknown_linux_musleabihf /build/musl-output/bin/armv7-linux-musleabihf-g++
ENV CFLAGS_armv7_unknown_linux_musleabihf "${ARCH_CFLAGS}"
ENV CXXFLAGS_armv7_unknown_linux_musleabihf "${ARCH_CFLAGS}"

RUN rustup target add armv7-unknown-linux-musleabihf

RUN /bin/bash -c 'echo -ne "[target.armv7-unknown-linux-musleabihf]\nlinker = \"armv7-linux-musleabihf-gcc\"\n"' > /usr/local/cargo/config

RUN apt-get update && apt-get install -y libclang-dev clang libaio-dev

ADD Cargo.toml /code/Cargo.toml
ADD Cargo.lock /code/Cargo.lock
ADD deps /code/deps

ENV HOME=/root
ENV USER=root

RUN mkdir -p /code/src && touch /code/src/lib.rs

WORKDIR /code
RUN cargo fetch

ADD . /code

ENV RUSTFLAGS="-C target-feature=+neon"
ENV RUST_BACKTRACE=full
ENV SYSROOT=/build/musl-output/armv7-linux-musleabihf

RUN cargo build --target=armv7-unknown-linux-musleabihf --release --example test

