FROM python:3.10-slim

ARG IMAGE_VERSION=本地构建

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn iproute2 iptables procps curl iputils-ping dnsutils tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN echo "$IMAGE_VERSION" > /app/version.txt

EXPOSE 8080

CMD ["python", "app/app.py"]
