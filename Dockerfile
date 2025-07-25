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
RUN apk add --no-cache bash bind-tools build-base cloc coreutils curl curl-dev dos2unix git go grep highlight jq make python3 python3-dev py3-setuptools py3-pip nano nano-syntax unzip vim wget zip zsh
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
RUN mkdir /tools /work
COPY scripts /tools/scripts
RUN chmod +x /tools/scripts/*.sh
RUN (find /tools/scripts -type f -name "*.sh") | xargs dos2unix
RUN bash /tools/scripts/install.sh
RUN find /usr/share/nano/ -iname "*.nanorc" -exec echo include {} \; >> /root/.nanorc
RUN echo "export SEMGREP_RULES_HOME=/tools/semgrep-rules" >> /root/.zshrc
RUN echo "export PATH=$PATH:/tools/scripts" >> /root/.zshrc
RUN echo "source /tools/pyenv/bin/activate" >> /root/.zshrc
RUN echo "alias cat-colorized='highlight -O ansi --force'" >> /root/.zshrc
RUN echo "alias list-rules-providers='find /tools -type d -name \"semgrep-rules*\" | cut -d'/' -f3 | sort'"  >> /root/.zshrc
COPY semgrep-rules-righettod /tools/semgrep-rules-righettod
RUN (find /tools/semgrep-rules-righettod -type f -name "*.yaml") | xargs dos2unix
WORKDIR /work
RUN rm -rf /tmp/*
RUN bash /tools/scripts/clean.sh
RUN rm /tools/scripts/install.sh /tools/scripts/clean.sh
RUN ( find /tools/scripts -type f) | xargs dos2unix
RUN chmod +x /tools/scripts/*
CMD ["/bin/zsh"]
