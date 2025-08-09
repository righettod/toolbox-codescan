# README

![Update the SemGrep scan reports of sandboxes codebase](https://github.com/righettod/toolbox-codescan/actions/workflows/update_sandbox_semgrep_scan_reports.yml/badge.svg?branch=main)

## Description

🔬 Tests and POC for the implementation of this [idea](https://github.com/righettod/toolbox-codescan/issues/2).

🐞 The sample test applications are custom-made to allow to perform specific tests.

📦 File [cwec_v4.17.xml](cwec_v4.17.xml) come from [here](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip).

## Execution steps of the POC

1. Start the Ollama model:

```shell
ollama pull qwen2.5-coder:latest
ollama run qwen2.5-coder:latest
```

2. Execute the script [poc.py](poc.py) with the index of the vulnerability in the SemGrep against which you want to run the test:

```shell
python poc.py 1
```

## Observations

* The model give a better using a single shot conversation (no history).
* I noticed that the model used is more prone to consider the vulnerability not present when the input is modified for sanitization purpose (even incorrect one). Indeed, if a valid regex block the flow to reach the vulnerable code, the model still considers the vulnerable code reachable even if providing a sample input that is blocked by the regex.
* I noticed that if a use a *temperature of 0* then the model always consider the vulnerability not present and provides incorrect justification from a technical perspective.

## References used

* <https://ollama.com/library/qwen2.5-coder>
* <https://github.com/appsecco/dvja>
* <https://cwe.mitre.org/data/xml/cwec_latest.xml.zip>
