"""
Script to enrich the json report of SemGrep with information regarding the possible false positive state.

Python dependencies:
    pip install langchain langchain-community langchain-ollama termcolor

Ollama dependencies:
    See README.md file for models setup.
"""
import json
import re
import colorama
import argparse
import xml.etree.ElementTree as ET
from tabulate import tabulate
from termcolor import colored
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate
from langchain.callbacks.base import BaseCallbackHandler

# Constants
DEFAULT_ENCODING = "utf-8"
CWE_XML_REFERENTIAL = "cwec_v4.17.xml"
CWE_XML_REFERENTIAL_NAMESPACES = {"cwe": "http://cwe.mitre.org/cwe-7"}
TECHNOLOGY_FILE_EXTENSION_MAPPING = {
    "py": "python",
    "js": "javascript",
    "rb": "ruby",
    "php": "php",
    "c": "c",
    "cpp": "c++",
    "java": "java",
    "cs": "csharp",
    "go": "go",
    "rs": "rust",
    "swift": "swift",
    "kt": "kotlin",
    "ts": "typescript"
}
OLLAMA_MODEL_CODE_EXTRACTION = "qwen2.5-coder"
OLLAMA_MODEL_CODE_EXTRACTION_TEMPERATURE = 0.0
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
OLLAMA_MODEL_FIX_BROKEN_JSON_REPLY = "qwen2.5-coder"
OLLAMA_MODEL_FIX_BROKEN_JSON_REPLY_TEMPERATURE = 0.0
SYSTEM_PROMPT_CODE_EXTRACTION = """You are an assistant specialized in extracting a function from a source code.

Given a global source code, a line number and a line of source code with a problem: You must extract the source code of the function in which the given line number is located.

You must only output the source code of the function and no more information.

Follow these steps to identify the right function:

1. Forget any previous context provided or used.
2. Identify in the global source code the location of the line number provided.
3. Extract the complete source code of the function in which the line number provided is located.
4. Add a comment on the top of the function with the following information:
  A. The line of code located on the line number provided.
  B. The explanation about why you have selected this function.
  C. The name of the function you have selected.
5. Verify that the function you selected contains the line of source code with a problem provided. If it is not the case then restart from zero.
"""

USER_PROMPT_TEMPLATE_CODE_EXTRACTION = """The line number is {start_line}.

The line of source code with a problem is `{source_code_affected_line_of_code}`.

The global source code is the following:

```{source_file_technology}
{source_file_content}
```"""

SYSTEM_PROMPT_CODE_REASONING = """You are an assistant specializing in source code analysis focusing on security vulnerabilities. Your primary objective is to determine if a given security vulnerability is truly present and exploitable within a provided source code.

Given a source code and a description of a security vulnerability, output a reply indicating if the given security vulnerability is really present or not. You must operate solely on the code provided and not make assumptions about potential exposure to code changes, external security controls, or other components.

**Strict Rules and Assumptions:**

* **No External Assumptions:** You must not make any assumptions about external security controls such as Web Application Firewalls (WAFs), reverse proxies, or external data sanitizers.
* **No Encoding Assumptions:** You must not assume a specific data encoding (e.g., UTF-8, ASCII) unless the source code explicitly specifies it.
* **No Privilege Assumptions:** You must assume a "worst-case scenario" security model, where a malicious actor has full control over the input.
* **Code is the Single Source of Truth:** The only valid security controls are those you can explicitly identify by tracing the data flow within the provided source code. If a control is not present in the code, it does not exist for the purpose of this analysis.

**Strict Evaluation of Code Logic:**

* **Fail-Fast on Rejection:** If any sanitization, validation, or transformation step (like a regular expression or a `replace` function) completely rejects the input or renders the proposed exploit ineffective, you must immediately conclude that the vulnerability is not present. The analysis ends here.
* **Regex is Absolute:** When a regular expression is used for validation, treat it as an absolute and unbreakable control. If the input does not match the regex, the payload is invalid, the vulnerable line is not reached, and the vulnerability is not present. No further payload analysis is required.
* **Payloads Only if Not Rejected:** Only attempt to formulate and test an exploit payload if no sanitization/validation step has already blocked the input.
* **Transformation Handling:** When the input undergoes transformations (e.g., `replace`, `replaceAll`, `trim`, `substring`), evaluate the exploit on the *transformed* data. If the transformation makes the payload ineffective, the vulnerability is not present.

**Decision Flow:**

1. **Identify Entry Points:** Analyze input parameters or external data sources that can reach the function.
2. **Trace Data Flow:** Follow the input to the vulnerable line. If it cannot reach, the vulnerability is not present.
3. **Check for Sanitization/Validation:** Identify and inspect processing applied to the input.
4. **Evaluate Effectiveness:** If a control fully blocks malicious input, the vulnerability is not present (stop analysis).
5. **Formulate Payload:** Only if no effective control exists, propose a payload that could exploit the vulnerability.
6. **Confirm Execution:** Show step-by-step how the payload is transformed, and confirm if it reaches the vulnerable code in an exploitable form.
7. **Final Decision:** Conclude whether the vulnerability is present. The vulnerability is present only if a valid payload exists that reaches the vulnerable line.

**Output Format:**

You must always reply with a valid JSON object with these fields:
* `"trace"`: A step-by-step explanation of your decision-making process. If the vulnerability is blocked early, explain why and stop.
* `"present"`: `"yes"` if the vulnerability is present, otherwise `"no"`.
* `"exploit"`: A payload string that can trigger the vulnerability if present. If `"present": "no"`, this must always be an empty string.
* `"reasoning_for_decision"`: A brief string that explains the final "yes" or "no" decision based on the rules.
"""

USER_PROMPT_TEMPLATE_CODE_REASONING = """This security vulnerability was identified in the given source code:
    {vulnerability_description}

    The type of security vulnerability is the following:
    {cwe_description}    

    The vulnerable line of source code is the following:

    ```{source_file_technology}
    {source_code_affected_line_of_code}
    ```

    This is the source code in which the vulnerability was identified:

    ```{source_file_technology}
    {source_file_function_content}
    ```"""

USER_PROMPT_TEMPLATE_FIX_BROKEN_JSON_REPLY = """I will provide a string that is a broken JSON object. Your task is to correct it and return only the valid, corrected JSON object.
**Rules for Correction:**

1. Ensure all keys and string values are enclosed in double quotes.
2. Remove any trailing commas from arrays and objects.
3. Correct any missing or misplaced brackets and braces.
4. Escape all double quotes (") and backslashes (\\) inside string values.
5. Remove any leading or trailing markdown formatting, including triple backticks (```json).

Do not add any extra text, explanations, or code block formatting. Return only the valid JSON.

This is the broken JSON object:

%s
"""


class ProcessingPhase:
    # code extraction
    # code reasoning
    # fixing json reply
    CODE_EXTRACTION = colored("code extraction  ", "light_cyan")
    CODE_REASONING = colored("code reasoning   ", "light_magenta")
    FIX_BROKEN_JSON_REPLY = colored("fixing json reply", "light_red")


class MyPromptPrinter(BaseCallbackHandler):
    def on_llm_start(self, serialized, prompts, **kwargs):
        print(colored("\n[Prompt Sent to Model]", "cyan"))
        for p in prompts:
            content = str(p)
            content = re.sub(r'Human:', "\n" + colored("Human:", "light_magenta"), content)
            content = re.sub(r'System:', "\n" + colored("System:", "light_green"), content)
            content = re.sub(r'AI:', "\n" + colored("AI:", "light_red"), content)
            print(content)
        print(colored("\n[End Prompt]", "cyan"))


class VulnerabilityInformation:
    start_line = 0
    cwe = ""
    cwe_description = ""
    description = ""
    source_file_content = ""
    source_code_affected_line_of_code = ""
    technology = ""
    file_path = ""
    semgrep_check_id = ""

    def get_display_id(self):
        content = f"check_id:{self.semgrep_check_id.split('.')[-1]}|file:{self.file_path.split('/')[-1]}"
        return content


def get_single_line_comment_expression(technology):
    if technology.lower() in ["python", "ruby"]:
        return "#"
    else:
        return "//"


def get_technology_from_file_extension(file_path):
    extension = file_path.split(".")[-1].lower()
    if extension in TECHNOLOGY_FILE_EXTENSION_MAPPING:
        return TECHNOLOGY_FILE_EXTENSION_MAPPING[extension].lower().strip()
    else:
        return "text"


def extract_raw_content(input, code_marker):
    output = input.replace(f"```{code_marker}", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r")
    return output


def extract_cwe_description(cwe, cwe_xml_document):
    cwe_id = cwe.split(":")[0].split("-")[1].strip(" ")
    root = cwe_xml_document.getroot()
    cwe_node = root.find(f".//cwe:Weakness[@ID='{cwe_id}']/cwe:Description", namespaces=CWE_XML_REFERENTIAL_NAMESPACES)
    cwe_description = cwe_node.text.strip()
    return cwe_description


def extract_vulnerability_information(semgrep_json_entry, source_code_base_folder, cwe_xml_document):
    # Load the information of the vulnerability that will be used for the user prompt
    # Make the lines of code unique to prevent the model to extract the false function when the vulnerable code exists in several locations
    # with the exact same syntax
    base_path = source_code_base_folder
    if not base_path.endswith("/"):
        base_path += "/"
    source_file_path = base_path + semgrep_json_entry["path"]
    source_file_technology = get_technology_from_file_extension(source_file_path)
    with open(source_file_path, mode="r", encoding=DEFAULT_ENCODING) as f:
        source_file_content = f.read()
    start_line = semgrep_json_entry["start"]["line"]
    description = semgrep_json_entry["extra"]["message"]
    cwe = semgrep_json_entry["extra"]["metadata"]["cwe"][0]  # Consider that the first CWE is the most relevant one
    source_code_affected_line_of_code = source_file_content.split("\n")[start_line-1].strip("\n\r\t ")  # Arrays are zero indexed
    source_file_content_updated = ""
    line_number = 1
    for line in source_file_content.splitlines():
        comment = get_single_line_comment_expression(source_file_technology) + str(line_number) + "\n"
        source_file_content_updated += line
        source_file_content_updated += comment
        line_number += 1
    source_code_affected_line_of_code_updated = (source_code_affected_line_of_code + get_single_line_comment_expression(source_file_technology) + str(start_line)).strip("\n\r\t ")
    source_file_content = source_file_content_updated
    source_code_affected_line_of_code = source_code_affected_line_of_code_updated
    vuln_info = VulnerabilityInformation()
    vuln_info.start_line = start_line
    vuln_info.cwe = cwe
    vuln_info.cwe_description = extract_cwe_description(cwe, cwe_xml_document)
    vuln_info.source_code_affected_line_of_code = source_code_affected_line_of_code
    vuln_info.source_file_content = source_file_content
    vuln_info.description = description
    vuln_info.technology = get_technology_from_file_extension(source_file_path)
    vuln_info.file_path = source_file_path
    vuln_info.semgrep_check_id = semgrep_json_entry["check_id"]
    return vuln_info


def print_progress(vuln_index, vuln_count, semgrep_vulnerabilities_object, processing_phase_name):
    print(f"\r[{processing_phase_name}] Analyzing vulnerability {vuln_index} on {vuln_count} => {semgrep_vulnerabilities_object.get_display_id():<80}", end="", flush=True)


def extra_json_fix(json_content):
    content = json_content
    content = re.sub(r'[\n\r\t]+', '', content)
    content = re.sub(r'[\s]{2,}', ' ', content)
    content = re.sub(r'[`]+', "'", content)
    if not content.startswith("{"):
        content = "{" + content
    if not content.endswith("}"):
        content = content + "}"
    return content


if __name__ == "__main__":
    colorama.init()
    parser = argparse.ArgumentParser(description="Script to enrich the json report of SemGrep with information regarding the possible false positive state.")
    required_params = parser.add_argument_group("required named arguments")
    required_params.add_argument("-i", action="store", dest="semgrep_data_file", help="Data file generated by SemGrep to use as data source.", required=True)
    required_params.add_argument("-b", action="store", dest="source_code_base_folder", help="Location of the root folder where source code scanned is located.", required=True)
    args = parser.parse_args()
    semgrep_data_file = args.semgrep_data_file
    source_code_base_folder = args.source_code_base_folder
    print(colored("[+] Initialization...", "yellow"))
    llm_code_extraction = OllamaLLM(model=OLLAMA_MODEL_CODE_EXTRACTION, temperature=OLLAMA_MODEL_CODE_EXTRACTION_TEMPERATURE)
    llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE)
    llm_fix_broken_json_reply = OllamaLLM(model=OLLAMA_MODEL_FIX_BROKEN_JSON_REPLY, temperature=OLLAMA_MODEL_FIX_BROKEN_JSON_REPLY_TEMPERATURE)
    cwe_xml_document = ET.parse(CWE_XML_REFERENTIAL)
    print("Done.")
    print(colored("[+] Load the collection of vulnerability identified by SemGrep...", "yellow"))
    with open(semgrep_data_file, mode="r", encoding=DEFAULT_ENCODING) as f:
        semgrep_data = json.load(f)
    semgrep_vulnerabilities = semgrep_data["results"]
    print(f"{len(semgrep_vulnerabilities)} entries loaded.")
    print(colored("[+] Map every vulnerability to its corresponding class instance...", "yellow"))
    semgrep_vulnerabilities_objects = []
    for semgrep_vulnerability in semgrep_vulnerabilities:
        semgrep_vulnerabilities_object = extract_vulnerability_information(semgrep_vulnerability, source_code_base_folder, cwe_xml_document)
        semgrep_vulnerabilities_objects.append(semgrep_vulnerabilities_object)
    print(f"{len(semgrep_vulnerabilities_objects)} objects mapped.")
    print(colored("[+] Process every vulnerability against local models...", "yellow"))
    index = 0
    semgrep_enriched_results = []
    semgrep_vulnerabilities_objects_count = len(semgrep_vulnerabilities_objects)
    prompt_template_code_extraction = ChatPromptTemplate.from_messages([("system", SYSTEM_PROMPT_CODE_EXTRACTION), ("human", USER_PROMPT_TEMPLATE_CODE_EXTRACTION)])
    chain_code_extraction = prompt_template_code_extraction | llm_code_extraction
    prompt_template_code_reasoning = ChatPromptTemplate.from_messages([("system", SYSTEM_PROMPT_CODE_REASONING), ("human", USER_PROMPT_TEMPLATE_CODE_REASONING)])
    chain_code_reasoning = prompt_template_code_reasoning | llm_code_reasoning
    for semgrep_vulnerabilities_object in semgrep_vulnerabilities_objects:
        print_progress(index+1, semgrep_vulnerabilities_objects_count, semgrep_vulnerabilities_object, ProcessingPhase.CODE_EXTRACTION)
        user_prompt_values = {"start_line": semgrep_vulnerabilities_object.start_line,
                              "source_file_technology": semgrep_vulnerabilities_object.technology,
                              "source_file_content": semgrep_vulnerabilities_object.source_file_content,
                              "source_code_affected_line_of_code": semgrep_vulnerabilities_object.source_code_affected_line_of_code}
        response = chain_code_extraction.invoke(user_prompt_values)
        source_file_function_content = extract_raw_content(response, semgrep_vulnerabilities_object.technology)
        print_progress(index+1, semgrep_vulnerabilities_objects_count, semgrep_vulnerabilities_object, ProcessingPhase.CODE_REASONING)
        conversation_config = {"callbacks": []}
        user_prompt_values = {"vulnerability_description": semgrep_vulnerabilities_object.description,
                              "cwe_description": semgrep_vulnerabilities_object.cwe_description,
                              "source_file_technology": semgrep_vulnerabilities_object.technology,
                              "source_file_function_content": source_file_function_content,
                              "source_code_affected_line_of_code": semgrep_vulnerabilities_object.source_code_affected_line_of_code}
        response = chain_code_reasoning.invoke(user_prompt_values, config=conversation_config)
        raw_response = extract_raw_content(response, "json")
        semgrep_vulnerability = semgrep_vulnerabilities[index]
        # Compact the response
        raw_response = re.sub(r'[\r\n\t]+', '', raw_response)
        raw_response = re.sub(r'[\s]{2,}', ' ', raw_response)
        # Sometime the output is not a valid json as some double quotes are not well escaped or other encoding issues
        semgrep_vulnerability["hints_for_analysis"] = {}
        try:
            json_response = json.loads(raw_response)
            semgrep_vulnerability["hints_for_analysis"]["details_as_object"] = json_response
        except:
            # Try to fix the broken json via a call to a model with specific instruction
            try:
                print_progress(index+1, semgrep_vulnerabilities_objects_count, semgrep_vulnerabilities_object, ProcessingPhase.FIX_BROKEN_JSON_REPLY)
                user_prompt_fix_broken_json = USER_PROMPT_TEMPLATE_FIX_BROKEN_JSON_REPLY % raw_response
                fixed_json_response = llm_fix_broken_json_reply.invoke(user_prompt_fix_broken_json)
                fixed_json_response = extra_json_fix(extract_raw_content(fixed_json_response, "json"))
                json_response = json.loads(fixed_json_response)
                semgrep_vulnerability["hints_for_analysis"]["details_as_object"] = json_response
            except Exception as e:
                semgrep_vulnerability["hints_for_analysis"]["details_as_text"] = raw_response
        vuln_is_present = re.findall(r'"present":\s*"(yes|no)"', raw_response, flags=re.IGNORECASE)[0].lower()
        semgrep_vulnerability["hints_for_analysis"]["vuln_is_false_positive"] = (vuln_is_present == "no")
        semgrep_enriched_results.append(semgrep_vulnerability)
        index += 1
    print(f"\rDone.{' ':<120}")
    print(colored("[+] Save enriched results...", "yellow"))
    semgrep_data_file_enriched = semgrep_data_file.replace(".json", "_enriched.json")
    semgrep_data["results"] = semgrep_enriched_results
    with open(semgrep_data_file_enriched, mode="w", encoding=DEFAULT_ENCODING) as f:
        json.dump(semgrep_data, f)
    print(colored("[+] Enrichment processing summary:", "yellow"))
    table_header = ["File", "SemGrep CheckID", "Identified as false positive?"]
    table_rows = []
    for semgrep_enriched_result in semgrep_enriched_results:
        filename = semgrep_enriched_result["path"].split("/")[-1]
        check_id = semgrep_enriched_result["check_id"].split(".")[-1]
        is_fp = semgrep_enriched_result["hints_for_analysis"]["vuln_is_false_positive"]
        table_rows.append([filename, check_id, is_fp])
    print(tabulate(table_rows, headers=table_header, numalign="right", stralign="left"))
