FROM rust:1.32.0

RUN apt-get update && apt-get install -y strace libclang-dev clang valgrind gdb

ADD Cargo.toml /code/Cargo.toml
ADD Cargo.lock /code/Cargo.lock
ADD deps /code/deps
RUN mkdir -p /code/src && touch /code/src/lib.rs

WORKDIR /code
RUN cargo fetch

ADD . /code

ENV RUST_BACKTRACE=full

CMD /bin/bash -c "cargo build --example test && RUST_BACKTRACE=full valgrind --num-callers=48 ./target/debug/examples/test"
#CMD /bin/bash -c "cargo build --release --example test && RUST_BACKTRACE=full ./target/release/examples/test"
#CMD /bin/bash -c "cargo test"
#CMD /bin/bash
