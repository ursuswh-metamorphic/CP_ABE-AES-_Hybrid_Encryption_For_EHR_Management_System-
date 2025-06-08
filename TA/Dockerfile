FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt PBC Library và các phụ thuộc cơ bản
RUN apt-get update && \
    apt-get install -y \
    libgmp-dev \
    build-essential \
    flex \
    bison \
    wget \
    tar && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure --prefix=/usr/local && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /tmp/pbc-0.5.14.tar.gz /tmp/pbc-0.5.14

# Cài đặt Python 3.7, pip và các phụ thuộc Charm-Crypto
WORKDIR /
RUN apt-get update && \
    apt-get install -y \
    software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y \
    python3.7 \
    python3.7-venv \
    libssl-dev \
    python3.7-dev \
    python3-setuptools \
    m4 \
    git \
    libffi-dev \
    python3-dev \
    python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Cài đặt Charm-Crypto
WORKDIR /app
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    ./configure.sh --python=$(which python3.7) && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /app/charm

# Sao chép mã nguồn ứng dụng và cài đặt các dependencies Python
WORKDIR /app
COPY . /app
# Đảm bảo pip cài đặt cho python3.7 bằng cách gọi python3.7 -m pip
RUN python3.7 -m pip install --no-cache-dir -r requirements.txt

EXPOSE 5001

# Lệnh khởi chạy ứng dụng
CMD ["python3.7", "ta_app.py"]
