# 💻 Code scan toolbox

[![Build and deploy the toolbox image](https://github.com/righettod/toolbox-codescan/actions/workflows/build_docker_image.yml/badge.svg?branch=main)](https://github.com/righettod/toolbox-codescan/actions/workflows/build_docker_image.yml) ![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=visualstudio) ![MadeWithDocker](https://img.shields.io/static/v1?label=Made%20with&message=Docker&color=blue&?style=for-the-badge&logo=docker) ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github)

## 🎯 Description

The goal of this image is to provide a ready-to-use toolbox to perform offline scanning of a code base using [Semgrep](https://semgrep.dev/) OSS version.

💡 The goal is to prevent any disclosure of the code base scanned.

## 📦 Build

Use the following set of command to build the docker image of the toolbox:

```bash
git clone https://github.com/righettod/toolbox-codescan.git
cd toolbox-codescan
docker build . -t righettod/toolbox-codescan
```

💡 The image is build every week and pushed to the GitHub image repository. You can retrieve it with the following command:

`docker pull ghcr.io/righettod/toolbox-codescan:main`

## 👨‍💻 Usage

> 🛑 it is important to add the option `--network none` to prevent any IO.

Use the following command to create a container of the toolbox:

```bash
docker run --rm -v "C:/Temp:/work" --network none -it ghcr.io/righettod/toolbox-codescan:main
# From here, use one of the provided script...
```

## 📋 Scripts

> 💡 [jq](https://jqlang.github.io/jq/) is installed and can be used to manipulate the result of a scan.

### Script 'scan_semgrep.sh'

Script to scan the current folder using a set of SEMGREP rules.

💻 Usage & Example:

```bash
$ pwd
/work/sample

$ /tools/scan_semgrep.sh
Usage:
   scan_semgrep.sh [RULES_FOLDER_NAME]

Call example:
    scan_semgrep.sh java
    scan_semgrep.sh php
    scan_semgrep.sh json

See sub folders in '/tools/semgrep-rules'.

Findings will be stored in file 'findings.json'.

$ /tools/scan_semgrep.sh java

┌────────────────┐
│ 1 Code Finding │
└────────────────┘

 src/burp/ActivityLogger.java
❯❯❱ tools.semgrep-rules.java.lang.security.audit.formatted-sql-string
       Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the
       SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement)
       instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

        91┆ stmt.execute(SQL_TABLE_CREATE);
```

## 🤝 Sources & credits

* <https://github.com/semgrep/semgrep-rules>
* <https://semgrep.dev/docs/getting-started/quickstart-oss>
