FROM ubuntu:18.04

# Install common dependencies
RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    clang \
    graphviz-dev \
    git \
    libgnutls28-dev \
    python-pip \
    nano \
    net-tools \
    vim \
    wget \
    software-properties-common \
    automake \
    libtool \
    unzip \
    tcpdump \
    telnet

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# Use ubuntu as the default username
USER ubuntu
WORKDIR /home/ubuntu

# Install gcovr for collecting code coverage information
RUN pip install gcovr

# Set up environment variables
ENV WORKDIR="/home/ubuntu"
ENV AFL="${WORKDIR}/aflnet"
ENV AFLNET="${WORKDIR}/aflnet"
ENV AFL_PATH="${WORKDIR}/aflnet"
ENV PATH="${PATH}:${WORKDIR}:${AFL}:${AFLNET}:/home/ubuntu/.local/bin"

# The following environment variables are set to make AFL work inside a Docker container
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1

# Copy files and folders from the host folder where Dockerfile is stored
COPY --chown=ubuntu:ubuntu aflnet $WORKDIR/aflnet
COPY --chown=ubuntu:ubuntu fotbot $WORKDIR/fotbot
COPY --chown=ubuntu:ubuntu results $WORKDIR/results

# Compile AFLNet
RUN cd $WORKDIR && \
    cd aflnet && \
    make clean all && \
    cd llvm_mode && \
    LLVM_CONFIG=llvm-config-6.0 make
