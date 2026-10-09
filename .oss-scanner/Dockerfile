# Copy this template to your project (at the location specified in your project.yaml), or otherwise add it
# parallel to your project.yaml at projects/<name>/Dockerfile.
# This file must set up the environment, install your project's dependencies and build the project.
# The scanner builds it with your repository as the build context, so `COPY . /src` puts the checkout inside
# the image. Network access is available during this Dockerfile build and is removed after this point, so
# all code that an agent might need to perform its tests must be fetched here.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    CC=clang \
    CXX=clang++
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang cmake ninja-build pkg-config git python3 \
      ccache curl libpcap-dev python3-pip software-properties-common tar wget xz-utils \
      net-tools tcpreplay python3-venv python3-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# --- example for a CMake project; replace with your build ---
# Build the project as its maintainers build it, with debug info (-g) and frame pointers. A step that fails the
# build, and primary_contact gets the log.
RUN cmake -S /src -B /src/build -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer" \
      -DLIGHT_PCAPNG_ZSTD=ON \
    && cmake --build /src/build -j"$(nproc)"

# Run the cheap tests so you know the image works, but do not let a failing test abort the build. Leave anything worth
# exercising (binaries, test drivers, examples) where threat_model.md says it is.
RUN python3 -m venv /src/.venv \
    && . /src/.venv/bin/activate \
    && python3 -m pip install -r /src/ci/run_tests/requirements.txt \
    && python3 /src/ci/run_tests/run_tests.py --interface eth0 --test-suites "packet" --build-dir /src/build
