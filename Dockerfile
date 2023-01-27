FROM python:alpine
ENV YARA_VERSION 4.2.3
ENV YARA_PY_VERSION 4.2.3
RUN apk add --no-cache openssl file jansson bison python3 tini su-exec
RUN apk add --no-cache -t .build-deps py3-setuptools \
  openssl-dev \
  jansson-dev \
  python3-dev \
  build-base \
  libc-dev \
  file-dev \
  automake \
  autoconf \
  libtool \
  flex \
  git \
  git \
  && set -x \
  && echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && sync \
  && ./configure --with-crypto \
  --enable-magic \
  --enable-cuckoo \
  --enable-dotnet \
  && make \
  && make install \
  && echo "Install yara-python..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_PY_VERSION https://github.com/VirusTotal/yara-python \
  && cd yara-python \
  && python3 setup.py build --dynamic-linking \
  && python3 setup.py install \
  && echo "Make test_rule..." \
  && mkdir /rules \
  && echo "rule dummy { condition: true }" > /rules/test_rule \
  && rm -rf /tmp/* \
  && apk del --purge .build-deps
COPY ludvig ludvig
COPY requirements.txt .
#no need to install yara-python as its already been compiled and installed
RUN sed -i 's/yara-python==[0-9\.]\{5\}//g' requirements.txt 
RUN pip install -r requirements.txt
ENTRYPOINT [ "python", "-m", "ludvig" ]