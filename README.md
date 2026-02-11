# 💻 Code scan toolbox

[![Build and deploy the toolbox image](https://github.com/righettod/toolbox-codescan/actions/workflows/build_docker_image.yml/badge.svg?branch=main)](https://github.com/righettod/toolbox-codescan/actions/workflows/build_docker_image.yml) ![MadeWitVSCode](https://img.shields.io/static/v1?label=Made%20with&message=VisualStudio%20Code&color=blue&?style=for-the-badge&logo=textpattern) ![MadeWithDocker](https://img.shields.io/static/v1?label=Made%20with&message=Docker&color=blue&?style=for-the-badge&logo=docker) ![AutomatedWith](https://img.shields.io/static/v1?label=Automated%20with&message=GitHub%20Actions&color=blue&?style=for-the-badge&logo=github)

## 🎯 Description

The goal of this image is to provide a ready-to-use toolbox to perform **offline scanning** of a code base.

💡 The goal is to **prevent any disclosure** of the code base scanned.

## 🛠️ Tools used

| Tool                                             | Usage                                                                                               |
|--------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| [Semgrep](https://github.com/semgrep/semgrep)    | Code scanning ([SAST](https://en.wikipedia.org/wiki/Static_application_security_testing) activity). |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Search for secrets/credentials/...                                                                  |

🔬 When **Semgrep** fails to detect a problem that I know exists, I try to suggest a new rule to the Semgrep [rules registry](https://github.com/semgrep/semgrep-rules):

* ✅ <https://github.com/semgrep/semgrep-rules/pull/3649>
* ✅ <https://github.com/semgrep/semgrep-rules/pull/3650>
* 🔬 <https://github.com/semgrep/semgrep-rules/pull/3706>
* 🔬 <https://github.com/semgrep/semgrep-rules/pull/3707>
* 🔬 <https://github.com/semgrep/semgrep-rules/pull/3708>
* 🔬 <https://github.com/semgrep/semgrep-rules/pull/3748>

💡 In order to be able to use proposed rules during the period in which corresponding PR are pending, all proposed rules are imported into the folder `/tools/semgrep-rules-righettod`:

* ❌ Indicates that the PR was **rejected**.
  * If a rule has its PR rejected then it stay permanently into this folder.
* ✅ Indicates that the PR was **merged**.
  * If a rule has its PR merged then it is removed from this folder as it become part of the semgrep rules registry.
  * Accepted rules are keep, as backup, into the folder **[archived-rules](archived-rules)**.
* 🔬 Indicates that the PR is **under review** from the SemGrep team.

😉 The folder `/tools/semgrep-rules-righettod` represent my custom semgrep rules registry.

## 📦 Build

💻 Use the following set of command to build the docker image of the toolbox:

```bash
git clone https://github.com/righettod/toolbox-codescan.git
cd toolbox-codescan
docker build . -t righettod/toolbox-codescan
```

💡 The image is build every week and pushed to the GitHub image repository. You can retrieve it with the following command:

`docker pull ghcr.io/righettod/toolbox-codescan:main`

## 👨‍💻 Usage

>[!CAUTION]
> It is important to add the option `--network none` to prevent any IO.

💻 Use the following command to create a container of the toolbox:

```bash
docker run --rm -v "C:/Temp:/work" --network none -it ghcr.io/righettod/toolbox-codescan:main
# From here, use one of the provided script...
```

## 📋 Scripts

> [!NOTE]
> 💡 [jq](https://jqlang.github.io/jq/) is installed and can be used to manipulate the result of a scan.

> [!NOTE]
> 💡 [regexploit](https://github.com/doyensec/regexploit) is installed and can be used to test exposure of a regular expression to [ReDOS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS).

> [!TIP]
> 📦 All scripts are stored in the folder `/tools/scripts` but they are referenced into the `PATH` environment variable.

### Script 'scan-code.sh'

> [!TIP]
> Semgrem rules from other providers are stored into the corresponding folder using the naming convention `semgrep-rules-[github-org-name]`. Use `../semgrep-rules-[github-org-name]/[rules_folder_name]` as `[RULES_FOLDER_NAME]` parameter to use them instead of the rules from the Semgrep registry.

> [!NOTE]
> Use the command `list-rules-providers` to see the list of rules imported from other providers.

Script to scan the current folder using a set of [SEMGREP rules](https://github.com/semgrep/semgrep-rules) with [SEMGREP](https://semgrep.dev/) OSS version.

🐞 Findings will be stored in file `findings.json`.

💡 This [script](https://github.com/righettod/toolbox-pentest-web/blob/master/scripts/generate-report-semgrep.py) can be used to obtains an overview of the findings identified and stored into the file `findings.json`. It is imported as the file `/tools/scripts/report-code.py`.

💻 Usage & Example:

```bash
$ pwd
/work/sample

$ scan-code.sh
Usage:
   scan-code.sh [RULES_FOLDER_NAME]

Call example:
    scan-code.sh java
    scan-code.sh php
    scan-code.sh json

See sub folders in '/tools/semgrep-rules'.

Findings will be stored in file 'findings.json'.

$ scan-code.sh java

┌────────────────┐
│ 1 Code Finding │
└────────────────┘

 src/burp/ActivityLogger.java
❯❯❱ tools.semgrep-rules.java.lang.security.audit.formatted-sql-string
       Detected a formatted string in a SQL statement. This could lead to SQL injection
       if variables in the SQL statement are not properly sanitized. Use a prepared
       statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement
       using 'connection.prepareStatement'.

        91┆ stmt.execute(SQL_TABLE_CREATE);
```

### Script 'scan-code-extended.sh'

> [!NOTE]
> In this script the notion of **technology** is the same than the notion of **RULES_FOLDER_NAME** used by the script `scan-code.sh`.

Perform the same processing than the script `scan-code.sh` but scan the current folder using all SEMGREP rules related to the target technology.

This script first gather all rules provided by all rules providers for the target technology and then use this consolidated set of rules for the scan.

### Script 'scan-secrets.sh'

> [!IMPORTANT]
> This [custom configuration file](https://github.com/righettod/toolbox-pentest-web/blob/master/templates/gitleaks-custom-config.toml) is used to define detection expressions.

Script to scan the current folder using [GITLEAKS](https://github.com/gitleaks/gitleaks) to find secrets into source files and git files. Git files scanning is only performed if a folder `.git` is present.

🐞 Leaks will be stored in files `leaks-gitfiles.json` and `leaks-sourcefiles.json`.

💡 This [script](https://github.com/righettod/toolbox-pentest-web/blob/master/scripts/generate-report-gitleaks.py) can be used to obtains an overview of the leaks identified and stored into the files `leaks-*.json`. It is imported as the file `/tools/scripts/report-secrets.py`.

💻 Usage & Example:

```bash
$ pwd
/work/sample

$ scan-secrets.sh
5:47PM INF scan completed in 78.1ms
5:47PM INF no leaks found
```

### Script 'scan-secrets-extended.sh'

Script to scan the current folder using a dictionary of **secret common variables names** ([source](https://gist.githubusercontent.com/EdOverflow/8bd2faad513626c413b8fc6e9d955669/raw/06a0ef0fd83920d513c65767aae258ecf8382bdf/gistfile1.txt)).

💡 The dictionary of secret common variables names referenced above is imported, as the file `/tools/secret-common-variable-names.txt`, during the build time of the image.

💻 Usage & Example:

```bash
$ pwd
/work/sample

$ scan-secrets-extended.sh
./config/db.properties:50:DB_PASSWORD=Password2024
```

### Script 'online-scan-secrets.sh'

Script to scan a collection of online git repositories using [GITLEAKS](https://github.com/gitleaks/gitleaks) to find secrets into source files and git files.

💡 The script [scan-secrets.sh](scripts/scan-secrets.sh) is used for the scan of a git repository once cloned.

💡 Use the script [online-scan-secrets-consolidate.py](scripts/online-scan-secrets-consolidate.py) to consolidate the generated data into a single file.

💻 Usage & Example:

```bash
$ online-scan-secrets.sh
Usage:
   online-scan-secrets.sh [FILE_WITH_COLLECTION_OF_GIT_REPO_URLS]

Call example:
    online-scan-secrets.sh repositories.txt

$ online-scan-secrets.sh repositories.txt
[*] Execution context:
List of git repositories URL   : repositories.txt (1030 entries)
Data collection storage folder : /work/data-collected
[*] Start repositories checking and data collection...
...
```

### Script 'filters-secrets.py'

Script to allow filtering a large leaks file that uses the [GITLEAKS](https://github.com/gitleaks/gitleaks) format, like for example, a file generated by the script [online-scan-secrets-consolidate.py](scripts/online-scan-secrets-consolidate.py).

💡The output allow to search for specific secrets using **grep** with differents regexes like `grep -B 4 -E 'ey[A-Za-z0-9]{15,}\.[A-Za-z0-9]{15,}\.[A-Za-z0-9_-]*' report.txt`.

💻 Usage:

```bash
filters-secrets.py leaks-consolidated.json
```

## 🔬 Analyse a .NET project

🤔 I noticed that SemGrep, with the community set of rules for CSharp, is not very effective.

💡 To address this:

* I found the tool [DevSkim](https://github.com/microsoft/DevSkim) provided by Microsoft that I added to the box. It's why I moved, from *alpine* to *ubuntu* for the base image, as I did not achieved to make it run on the *alpine* based image.
* I created and added this [script](https://github.com/righettod/toolbox-pentest-web/blob/master/scripts/generate-report-devskim.py) as `report-code-devskim.py` to explore the results of the scan.
* I created the alias `scan-code-devskim` to scan the current folder with `DevSkim` and generate the results in the json file `findings.json` to stay consistent with other scripts of the toolbox.

## ⚗️ Misc

The folder [misc](misc/) contains several POC exploring the usage of AI (local model) in the context of a secure code review activity.

## 🤝 Sources & credits

### Semgrep analysis rules providers

* <https://github.com/semgrep/semgrep-rules>
* <https://github.com/trailofbits/semgrep-rules>
* <https://github.com/ajinabraham/njsscan>

### Tools

* <https://semgrep.dev/docs/getting-started/quickstart-oss>
* <https://semgrep.dev/docs/ignore-oss>
* <https://gitleaks.io/>
* <https://github.com/doyensec/regexploit>
* <https://github.com/microsoft/DevSkim>
