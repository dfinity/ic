FROM ubuntu:20.04

RUN apt -yq update && \
    apt -yq install --no-install-recommends git curl wget ca-certificates

RUN groupadd -g 1000 ubuntu && useradd -ms /bin/bash -u 1000 -g 1000 ubuntu

USER ubuntu

CMD ["/bin/bash"]
