FROM infsec/monpoly:1.4.1
RUN apk add --update python3=3.9.5-r2 py3-pip py3-psutil=5.8.0-r1
WORKDIR /work
COPY . /work
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3"]
