![Update the GitLeaks scan reports of sandboxes codebase](https://github.com/righettod/toolbox-codescan/actions/workflows/poc01_update_sandbox_gitleaks_scan_reports.yml/badge.svg)

## Description

🔬 Tests and POC for the implementation of this [idea](https://github.com/righettod/toolbox-codescan/issues/4).

🐞 The sample test applications are custom-made to allow to perform specific tests.

## Execution steps of the POC

> [!NOTE]
> The name of the model used is `qwen2.5-coder:latest` ([documentation](https://ollama.com/library/qwen2.5-coder)).

1. Start the Ollama model:

```shell
ollama pull [MODEL_NAME]
ollama run [MODEL_NAME]
```

2. Execute the script [poc.py](poc.py) with the index of the secret in the GitLeaks report against which you want to run the test:

```shell
# Call option n°1 with the index of the secret
$ python poc.py 0
# Call option n°2 with default index to 0
$ python poc.py
```

## Prompts history

### Code reasoning

#### System prompt version 1.0

> [!NOTE]
> Manually written by me.

```text

```

#### User prompt version 1.0

> [!NOTE]
> Manually written by me.

```text
The programming language is `{secret_file_technology}`.

The text value to analyse is `{secret_value}.`
```
