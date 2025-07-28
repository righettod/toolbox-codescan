"""
Code to test the idea and prompts.

Python dependencies:
    pip install langchain langchain-community langchain-ollama termcolor

Ollama dependencies
    ollama pull qwen2.5-coder:latest
    ollama run qwen2.5-coder:latest
"""
import json
from termcolor import colored
import xml.etree.ElementTree as ET
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate

# Constants
SANDBOX_TECHNOLOGY = "java"
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL = "qwen2.5-coder"
CWE_XML_REFERENTIAL = "cwec_v4.17.xml"
CWE_XML_REFERENTIAL_NAMESPACES = {"cwe": "http://cwe.mitre.org/cwe-7"}
VULNERABLE_CODEBASE_FOLDER = f"vulnerable-codebase/{SANDBOX_TECHNOLOGY}/"
INDEX_OF_TESTED_VULNERABILITY = 1  # Zero based


def extract_raw_content(input, code_marker=SANDBOX_TECHNOLOGY):
    output = input.replace(f"```{code_marker}", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r")
    return output


# Load the SemGrep findings
with open(f"findings-{SANDBOX_TECHNOLOGY}.json", mode="r", encoding=DEFAULT_ENCODING) as f:
    vulnerabilities = json.load(f)

# Select one vulnerability for the POC
vulnerability = vulnerabilities["results"][INDEX_OF_TESTED_VULNERABILITY]

# Load the information of the vulnerability that
# will be used for the user prompt
source_file_path = VULNERABLE_CODEBASE_FOLDER + vulnerability["path"]
source_file_technology = SANDBOX_TECHNOLOGY
with open(source_file_path, mode="r", encoding=DEFAULT_ENCODING) as f:
    source_file_content = f.read()
start_line = vulnerability["start"]["line"]
start_column = vulnerability["start"]["col"]
end_line = vulnerability["end"]["line"]
end_column = vulnerability["end"]["col"]
vulnerability_description = vulnerability["extra"]["message"]
cwe = vulnerability["extra"]["metadata"]["cwe"][0]  # Consider that the first CWE is the most relevant one

# Load the description of the CWE via its ID
cwe_id = cwe.split(":")[0].split("-")[1].strip(" ")
tree = ET.parse(CWE_XML_REFERENTIAL)
root = tree.getroot()
cwe_node = desc = root.find(f".//cwe:Weakness[@ID='{cwe_id}']/cwe:Description", namespaces=CWE_XML_REFERENTIAL_NAMESPACES)
cwe_description = cwe_node.text.strip()

# Use the model to extract the code of the function (or method) containing the range of code specified containing the vulnerability
# Use a deterministic behavior of the model via a temperature to zero
llm_deterministic = OllamaLLM(model=OLLAMA_MODEL, temperature=0.0)
system_prompt = """You are an AI assistant specializing in extracting parts of a source code.
Given a source code and a line number, you must extract the source code of the function in which the given line is located.
You must only output the source code of the function and no more information.
"""

user_prompt_template = """This is the source code:
```{source_file_technology}
{source_file_content}
```

The line number is {start_line}.
"""
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt_template)])
chain = prompt_template | llm_deterministic
user_prompt_values = {"start_line": start_line,
                      "source_file_technology": source_file_technology,
                      "source_file_content": source_file_content}
response = chain.invoke(user_prompt_values)
source_file_function_content = extract_raw_content(response)
print(colored("=> FUNCTION CODE:", "yellow"))
print(source_file_function_content)


# Create the final system prompt
system_prompt = """You are an AI assistant specializing in code analysis focusing on security vulnerabilities.
Given a source code, output a reply indicating if the given security vulnerability is really present or not.
Your reply will be a json object where you will set "Yes" into the json attribute "present" if the vulnerability is really present and "No" if the vulnerability is not present.
You will add the technical reason that justify your decision into the json attribute "explanation".
When referring to specific lines, use line numbers where possible."""

# Create the final user prompt
user_prompt_template = """This security vulnerability was identified in the given source code:
{vulnerability_description}

The type of security vulnerability is the following:
{cwe_description}

This is the source code in which the vulnerability was identified:

```{source_file_technology}
{source_file_content}
```"""

user_prompt_values = {"vulnerability_description": vulnerability_description,
                      "cwe_description": cwe_description,
                      "source_file_technology": source_file_technology,
                      "source_file_content": source_file_function_content}


# Use the model to analyse the vulnerability against the code snippet (function/method)
# Use a default behavior of the model via a temperature to default value
llm = OllamaLLM(model=OLLAMA_MODEL)
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt_template)])
chain = prompt_template | llm

# Invoke the chain with the user prompt values
response = chain.invoke(user_prompt_values)
raw_response = extract_raw_content(response, "json")
print("")
print(colored("=> MODEL REPLY:", "yellow"))
print(raw_response)
