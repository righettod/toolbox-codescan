# README

![Update the SemGrep scan reports of sandboxes codebase](https://github.com/righettod/toolbox-codescan/actions/workflows/update_sandbox_semgrep_scan_reports.yml/badge.svg?branch=main)

## Description

🔬 Tests and POC for the implementation of this [idea](https://github.com/righettod/toolbox-codescan/issues/2).

🐞 The sample test application with vulnerabilites was taken from this [project](https://github.com/appsecco/dvja).

📦 File [cwec_v4.17.xml](cwec_v4.17.xml) come from [here](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip).

## Execution steps of the POC

1. Start the Ollama model:

```shell
ollama pull qwen2.5-coder:latest
ollama run qwen2.5-coder:latest
```

2. Run the script [poc.py](poc.py).

## Obervations

None for the moment.

## References used

* <https://ollama.com/library/qwen2.5-coder>
* <https://github.com/appsecco/dvja>
* <https://cwe.mitre.org/data/xml/cwec_latest.xml.zip>
