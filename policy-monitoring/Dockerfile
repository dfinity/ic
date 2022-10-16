FROM infsec/monpoly:1.4.2
ARG MONPOLY_PIPELINE_GIT_REVISION
ENV MONPOLY_PIPELINE_GIT_REVISION=$MONPOLY_PIPELINE_GIT_REVISION
RUN apk add --update python3=3.9.13-r1 py3-pip py3-psutil=5.8.0-r1
WORKDIR /work
COPY . /work
RUN pip3 install -r requirements.txt

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["/work/main.py"]
