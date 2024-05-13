FROM debian:12-slim

WORKDIR /mnt

SHELL [ "/bin/bash", "-c" ]

RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y \
        binutils-mingw-w64-x86-64 \
        bison \
        build-essential \
        bzip2 \
        ca-certificates \
        expat \
        file \
        flex \
        g++-12 \
        gcc-12 \
        gcc-mingw-w64-x86-64 \
        git \
        gnupg \
        gperf \
        libexpat-dev \
        libgmp-dev \
        libssl-dev \
        make \
        meson \
        ninja-build \
        patch \
        texinfo \
        wget \
        xz-utils \
        yasm \
        zip \
        zlib1g-dev \
    && apt remove --purge -y gnupg \
    && apt autoremove --purge -y \
    && apt clean
