"""
Script to enrich the json report of GitLeaks with information regarding the possible false positive state.

Python dependencies:
    pip install langchain langchain-community langchain-ollama termcolor pygments requests tabulate

Ollama dependencies:
    See README.md file for models setup.
"""
import json
import colorama
import argparse
import requests
from tabulate import tabulate
from termcolor import colored
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
from pygments.lexers import get_lexer_for_filename
from pygments.util import ClassNotFound

# Constants
DEFAULT_ENCODING = "utf-8"
WEAK_PASSWORDS_DICT_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2024-197_most_used_passwords.txt"
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
OLLAMA_MODEL_RESPONSE_TIMEOUT_IN_SECONDS = 60
SYSTEM_PROMPT_CODE_REASONING = """You are an assistant specializing in secret analysis focusing on analysis if a value is a secret. Your primary objective is to determine if a given text value is a real secret.

Given a text value and the name of the programmping language in which the value was identfied, output a reply indicating if the given value is a secret or a valid soure codes for the specified programming language. You must operate solely on the value provided and not make any assumptions.

**Decision Flow:**

**Data Analysis** - Follow the steps below in sequence. Once a condition allow you to conclude the analysis then **proceed directly** to the **Output Format**:

1. Identify if the provided text value is a **know weak password** leveraging the function provided when needed:
  * **If YES:** Conclude **IS a real secret**.
  * **If NO:** Proceed to Step 2.
2. Identify if the provided text value is a valid source code for the provided name of programming language:
  * **If YES:** Conclude **NOT a real secret**.
  * **If NO:** Proceed to Step 3.
3. Identify if the provided text value is a reference to an **environment variable** from an operating system perspective:
  * **If YES:** Conclude **NOT a real secret**.
  * **If NO:** Proceed to Step 4.
4. Identify if the provided text value is a **Expression Language placeholder** from the specified programming language perspective:
  * **If YES:** Conclude **NOT a real secret**.
  * **If NO:** Proceed to Step 5.
5. Identify if the provided text value is a asymmetric private key or a **hash** like MD5, SHA1, BCRYPT, etc.:
  * **If YES:** Conclude **IS a real secret**.
  * **If NO:** Proceed to Step 6.
6. Identify if the provided text value is a word that **you know**:
  * **If YES:** Conclude **NOT a real secret**.
  * **If NO:** Conclude **IS a real secret** and it require manual validation because the value is unknown. 

**Output Format:**

You must **always** reply with a single valid JSON object containing **only** these fields:
* `"trace"`: A concise, step-by-step summary detailing which check was applied and why, leading to the final decision. Reference the step number (1-6) that yielded the final result.
* `"is_real_secret"`: `"yes"` if the provided data is considered a real secret, otherwise `"no"`.
"""

USER_PROMPT_TEMPLATE_CODE_REASONING = """The programming language is `{secret_file_technology}`.

The text value to analyse is `{secret_value}`.

Observation from weak password tool: `{weak_password_check}`.
"""


class SecretInformation:
    value = ""
    technology = ""
    gitleaks_tag = ""
    gitleaks_fingerprint = ""

    def get_display_id(self):
        content = self.gitleaks_fingerprint.split("/")[-1]
        return content


def is_know_weak_password(value: str, weak_password_list: list) -> str:
    if value in weak_password_list:
        return f"YES — '{value}' **IS** a known weak password."
    else:
        return f"NO — '{value}' **IS NOT** a known weak password."


def extract_raw_content(input):
    output = input.replace(f"```json", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r*")
    return output


def get_technology_from_filename(filename):
    try:
        return get_lexer_for_filename(filename).name
    except ClassNotFound:
        return "Text only"


def extract_secret_information(gitleaks_json_entry):
    # Load the information of the secret that will be used for the user prompt
    secret_value = gitleaks_json_entry["Secret"]
    secret_file_technology = get_technology_from_filename(gitleaks_json_entry["File"])
    gitleaks_tag = gitleaks_json_entry["Tags"][0]  # Use only the first tag
    gitleaks_fingerprint = gitleaks_json_entry["Fingerprint"]
    # For credentials in URL then extract the password
    if gitleaks_json_entry["RuleID"] == "generic-secret-in-url":
        secret_value = secret_value.split(":")[1]
    secret_info = SecretInformation()
    secret_info.value = secret_value
    secret_info.technology = secret_file_technology
    secret_info.gitleaks_tag = gitleaks_tag
    secret_info.gitleaks_fingerprint = gitleaks_fingerprint
    return secret_info


def print_progress(secret_index, secret_count, gitleaks_secret_object):
    print(f"\rAnalyzing secret {secret_index} on {secret_count} => {gitleaks_secret_object.get_display_id():<80}", end="", flush=True)


if __name__ == "__main__":
    colorama.init()
    parser = argparse.ArgumentParser(description="Script to enrich the json report of GitLeaks with information regarding the possible false positive state.")
    required_params = parser.add_argument_group("required named arguments")
    required_params.add_argument("-i", action="store", dest="gitleaks_data_file", help="Data file generated by GitLeaks to use as data source.", required=True)
    args = parser.parse_args()
    gitleaks_data_file = args.gitleaks_data_file
    print(colored("[+] Initialization...", "yellow"))
    llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE, timeout=OLLAMA_MODEL_RESPONSE_TIMEOUT_IN_SECONDS)
    system_prompt = SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT_CODE_REASONING)
    human_prompt = HumanMessagePromptTemplate.from_template(USER_PROMPT_TEMPLATE_CODE_REASONING)
    prompt_template = ChatPromptTemplate.from_messages([system_prompt, human_prompt])
    print("Done.")
    print(colored("[+] Load the list of weak passwords...", "yellow"))
    response = requests.get(WEAK_PASSWORDS_DICT_URL)
    weak_password_list = response.text.splitlines()
    print("Done.")
    print(colored("[+] Load the collection of secrets identified by GitLeaks...", "yellow"))
    with open(gitleaks_data_file, mode="r", encoding=DEFAULT_ENCODING) as f:
        gitleaks_secrets = json.load(f)
    print(f"{len(gitleaks_secrets)} entries loaded.")
    print(colored("[+] Map every secret to its corresponding class instance...", "yellow"))
    gitleaks_secret_objects = []
    for gitleaks_secret in gitleaks_secrets:
        gitleaks_secret_object = extract_secret_information(gitleaks_secret)
        gitleaks_secret_objects.append(gitleaks_secret_object)
    gitleaks_secret_objects_count = len(gitleaks_secret_objects)
    print(f"{gitleaks_secret_objects_count} objects mapped.")
    print(colored("[+] Process every secret against the local model...", "yellow"))
    gitleaks_enriched_results = []
    index = 0
    for gitleaks_secret_object in gitleaks_secret_objects:
        print_progress(index+1, gitleaks_secret_objects_count, gitleaks_secret_object)
        weak_password_hint = is_know_weak_password(gitleaks_secret_object.value, weak_password_list)
        user_prompt_values = {"secret_file_technology": gitleaks_secret_object.technology, "secret_value": gitleaks_secret_object.value, "weak_password_check": weak_password_hint}
        final_prompt = prompt_template.format(**user_prompt_values)
        response = llm_code_reasoning.invoke(final_prompt)
        raw_response = extract_raw_content(response)
        json_response = json.loads(raw_response)
        gitleaks_enriched_result = gitleaks_secrets[index]
        gitleaks_enriched_result["HintsForAnalysis"] = json_response
        gitleaks_enriched_results.append(gitleaks_enriched_result)
        index += 1
    print(f"\rDone.{' ':<120}")
    print(colored("[+] Save enriched results...", "yellow"))
    gitleaks_data_file_enriched = gitleaks_data_file.replace(".json", "_enriched.json")
    with open(gitleaks_data_file_enriched, mode="w", encoding=DEFAULT_ENCODING) as f:
        json.dump(gitleaks_enriched_results, f)
    print(colored("[+] Enrichment processing summary:", "yellow"))
    table_header = ["Secret location", "GitLeaks RuleID", "Identified as false positive?"]
    table_rows = []
    for gitleaks_enriched_result in gitleaks_enriched_results:
        filename = gitleaks_enriched_result["Fingerprint"].split("/")[-1]
        rule_id = gitleaks_enriched_result["RuleID"]
        is_fp = (gitleaks_enriched_result["HintsForAnalysis"]["is_real_secret"].upper() == "NO")
        table_rows.append([filename, rule_id, is_fp])
    print(tabulate(table_rows, headers=table_header, numalign="right", stralign="left"))
