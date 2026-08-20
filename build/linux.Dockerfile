# The Linux release build environment.
#
# Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
#
#     docker build -f build/linux.Dockerfile -t compakt-build .
#     docker run --rm -v "<repo parent>:/work" compakt-build <command>
#
# WHY A CUSTOM IMAGE
# ------------------
# The binary must run on distributions older than the one that built it,
# and glibc is forward-compatible only: a binary linked against 2.39
# refuses to start on 2.35 with a version error, while one linked against
# 2.28 runs everywhere above it. So the build host has to be OLD, which
# is the opposite of the usual instinct.
#
# manylinux_2_28 is purpose-built for that -- glibc 2.28, reaching back
# to RHEL 8, Debian 10 and Ubuntu 18.04 -- and it ships CPython 3.14
# already. It cannot be used as-is:
#
#     ERROR: Python was built without a shared library, which is
#     required by PyInstaller.
#
# The manylinux CPythons are static, because building wheels never needs
# libpython.so. PyInstaller does need it. Rather than give up the glibc
# floor and move to a newer base -- python:3.14-bookworm would cost
# every Ubuntu 22.04 user, which is a large share of the audience this
# CLI is for -- this image compiles one shared CPython at 2.28.
#
# The compile happens once, at image build time. Every release build
# afterwards reuses it.

FROM quay.io/pypa/manylinux_2_28_x86_64

ARG PYTHON_VERSION=3.14.7

# libarchive is a RUNTIME dependency probed through ctypes, not a build
# input: core.decompressor loads it to decide which Tier 2 formats this
# build can honestly advertise. Without it here, the frozen binary would
# report a shorter format list than the machine it lands on supports.
#
# dpkg supplies dpkg-deb, which build/linux.py needs to assemble the
# .deb. It is unusual on an RPM host and entirely deliberate.
#
# The -devel packages are what CPython links its optional extension
# modules against AT COMPILE TIME. A missing one does not fail the
# build: configure notes it, carries on, and produces an interpreter
# quietly lacking that module.
#
# libzstd-devel is the one that bites. Python 3.14 added the stdlib
# `compression.zstd`, backed by the `_zstd` extension. Without the
# headers here, py7zr -- which imports it on 3.14 -- fails to import,
# and Compakt drops .7z from its supported formats with no error
# anywhere. The manylinux CPython has it, which is why this only
# appeared once the interpreter was built by hand.
RUN yum install -y -q \
        libarchive libarchive-devel \
        dpkg dpkg-dev \
        openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel \
        libzstd-devel \
    && yum clean all

# libzstd, from source, because the distribution's is too old.
#
# AlmaLinux 8 ships libzstd 1.4.4. CPython 3.14's `_zstd` needs newer,
# so `configure` skips the module -- without failing -- and the
# interpreter comes out unable to import compression.zstd. py7zr then
# will not import, and .7z vanishes from Compakt's format list with no
# error at any layer.
#
# This is the cost of an old glibc floor: an old base distribution has
# old everything. Building the one library that is too old is cheaper
# than giving up the reach, and it is a minute of compile time.
ARG ZSTD_VERSION=1.5.7
RUN cd /usr/src \
    && curl -fsSLO "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz" \
    && tar xzf "zstd-${ZSTD_VERSION}.tar.gz" \
    && cd "zstd-${ZSTD_VERSION}" \
    && make -j"$(nproc)" \
    && make install PREFIX=/usr/local \
    && cd / && rm -rf /usr/src/zstd* \
    && ldconfig

ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH}"

# CPython, shared this time. --enable-optimizations is deliberately NOT
# used: it roughly triples the build for a speed gain that does not
# survive being frozen and shipped, and this interpreter only ever runs
# PyInstaller.
RUN cd /usr/src \
    && curl -fsSLO "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
    && tar xzf "Python-${PYTHON_VERSION}.tgz" \
    && cd "Python-${PYTHON_VERSION}" \
    && ./configure --enable-shared --prefix=/usr/local \
                   LDFLAGS="-Wl,-rpath,/usr/local/lib" \
    && make -j"$(nproc)" \
    && make altinstall \
    && cd / && rm -rf /usr/src/Python*

ENV PATH="/usr/local/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

# Fail loudly at image build time rather than at release time.
# The checks and the reasoning behind each one live in the script.
COPY build/check_interpreter.py /usr/local/bin/check_interpreter.py
RUN python3.14 /usr/local/bin/check_interpreter.py

RUN python3.14 -m venv /opt/venv \
    && /opt/venv/bin/pip install --quiet --upgrade pip

ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /work/compakt
