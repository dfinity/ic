FROM docker.io/selenium/standalone-chrome:113.0

USER root

COPY ./certs/ /etc/certs

RUN apt-get update -y && \
    apt-get -y install \
    libnss3-tools && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN mkdir -p -m755 /home/seluser/.pki/nssdb && \
    certutil -d sql:/home/seluser/.pki/nssdb -N --empty-password && \
    certutil -d sql:/home/seluser/.pki/nssdb -A -t "C,," -n rootca -i /etc/certs/rootCA.pem
