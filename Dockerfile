FROM alpine:3
LABEL org.opencontainers.image.authors="dominique.righetto@gmail.com"
LABEL org.opencontainers.image.vendor="Dominique RIGHETTO (righettod)"
LABEL org.opencontainers.image.url="https://github.com/righettod/toolbox-codescan"
LABEL org.opencontainers.image.source="https://github.com/righettod/toolbox-codescan"
LABEL org.opencontainers.image.documentation="https://github.com/righettod/toolbox-codescan"
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
LABEL org.opencontainers.image.title="toolbox-codescan"
LABEL org.opencontainers.image.description="Customized toolbox to perform offline scanning of a code base with Semgrep."
LABEL org.opencontainers.image.base.name="righettod/toolbox-codescan:main"
ENV DEBIAN_FRONTEND=noninteractive
RUN apk update
RUN apk add --no-cache bash bind-tools build-base coreutils curl curl-dev dos2unix git grep jq python3 python3-dev py3-setuptools py3-pip nano nano-syntax unzip vim wget zip zsh
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
RUN mkdir /tools /work
COPY scan_semgrep.sh /tools/scan_semgrep.sh
RUN dos2unix /tools/scan_semgrep.sh
RUN chmod +x /tools/scan_semgrep.sh
COPY add_semgrep.sh /tmp/add_semgrep.sh
RUN dos2unix /tmp/add_semgrep.sh
RUN chmod +x /tmp/add_semgrep.sh
RUN bash /tmp/add_semgrep.sh
RUN echo "source /tools/pyenv/bin/activate" >> /root/.zshrc
RUN find /usr/share/nano/ -iname "*.nanorc" -exec echo include {} \; >> /root/.nanorc
RUN echo "export SEMGREP_RULES_HOME=/tools/semgrep-rules" >> /root/.zshrc
RUN echo "alias scan='bash /tools/scan_semgrep.sh'" >> /root/.zshrc
WORKDIR /work
RUN rm -rf /tmp/*
CMD ["/bin/zsh"]
