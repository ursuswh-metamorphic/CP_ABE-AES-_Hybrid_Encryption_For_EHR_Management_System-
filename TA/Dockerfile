# Dockerfile tối ưu hóa (Multi-stage Build) cho Dịch vụ TA
# Phiên bản cuối cùng, sửa lỗi biên dịch liboqs thành thư viện chia sẻ.

# =============================================================================
# Giai đoạn 1: Builder - Biên dịch C-libs và tải mã nguồn Python
# =============================================================================
FROM ubuntu:22.04 as builder

# Đặt biến môi trường để tránh các câu hỏi tương tác khi cài đặt
ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt các công cụ biên dịch C/C++ và git
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    tar \
    flex \
    bison \
    cmake \
    ninja-build \
    libgmp-dev \
    libssl-dev \
    git \
    ca-certificates \
    python3.10 \
    python3.10-dev \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# --- 1. Biên dịch và cài đặt PBC Library ---
RUN wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf pbc-0.5.14*

# --- 2. Biên dịch và cài đặt Charm-Crypto ---
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    python3.10 -m pip install setuptools wheel && \
    sed -i 's|http://pypi.python.org|https://pypi.python.org|' distribute_setup.py && \
    ./configure.sh --python=$(which python3.10) && \
    make && \
    make install && \
    cd .. && \
    rm -rf charm

# --- 3. Biên dịch và cài đặt liboqs (động cơ C của OQS) ---
# SỬA LỖI: Bật cờ BUILD_SHARED_LIBS để tạo ra file .so mà Python cần
RUN wget --no-check-certificate https://github.com/open-quantum-safe/liboqs/archive/refs/heads/main.tar.gz -O liboqs.tar.gz && \
    tar -xvf liboqs.tar.gz && \
    mv liboqs-main liboqs && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    cd ../.. && \
    rm -rf liboqs liboqs.tar.gz

# --- 4. Tải mã nguồn liboqs-python (KHÔNG cài đặt ở đây) ---
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python.git

# --- Giai đoạn 1 kết thúc ---


# =============================================================================
# Giai đoạn 2: Final Image - Tạo image cuối cùng để chạy ứng dụng
# =============================================================================
FROM ubuntu:22.04

# Đặt biến môi trường
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Cài đặt các gói cần thiết để CHẠY ứng dụng và các công cụ build cho pip
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.10 \
    python3.10-dev \
    python3-pip \
    libgmp-dev \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Sao chép các thư viện C/C++ đã được biên dịch từ giai đoạn builder
COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/include/ /usr/local/include/
COPY --from=builder /usr/local/lib/python3.10/dist-packages/ /usr/local/lib/python3.10/dist-packages/


# Thêm đường dẫn thư viện vào cấu hình của linker và chạy ldconfig
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig

# Tạo một thư mục cho ứng dụng
WORKDIR /app

# ---- BƯỚC CÀI ĐẶT QUAN TRỌNG ----
# Sao chép mã nguồn liboqs-python và cài đặt nó bằng "pip install ."
COPY --from=builder /build/liboqs-python /app/liboqs-python
RUN python3.10 -m pip install --no-cache-dir ./liboqs-python

# Bây giờ mới cài đặt các gói còn lại từ requirements.txt
# File requirements không cần chứa Charm-Crypto hay oqs-python
COPY requirements.txt .
RUN python3.10 -m pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn của ứng dụng vào image
COPY . .

# Mở port 5001
EXPOSE 5001

# Lệnh để khởi chạy ứng dụng khi container bắt đầu
CMD ["python3.10", "ta_app.py"]
