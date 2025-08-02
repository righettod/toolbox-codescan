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

# Execution context
INDEX_OF_TESTED_VULNERABILITY = 0  # Zero based


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
source_code_affected_line_of_code = source_file_content.split("\n")[start_line-1].strip("\n\r\t ")  # Arrays are zero indexed
print(colored("=> VULNERABILITY LINE NUMBER AND LINE OF CODE:", "yellow"))
print(start_line)
print(source_code_affected_line_of_code)
print("")

# Load the description of the CWE via its ID
cwe_id = cwe.split(":")[0].split("-")[1].strip(" ")
tree = ET.parse(CWE_XML_REFERENTIAL)
root = tree.getroot()
cwe_node = desc = root.find(f".//cwe:Weakness[@ID='{cwe_id}']/cwe:Description", namespaces=CWE_XML_REFERENTIAL_NAMESPACES)
cwe_description = cwe_node.text.strip()

# Use the model to extract the code of the function (or method) containing the range of code specified containing the vulnerability
# Use a deterministic behavior of the model via a temperature to zero
llm_deterministic = OllamaLLM(model=OLLAMA_MODEL, temperature=0.0)
system_prompt = """You are an assistant specialized in extracting a function from a source code.

Given a global source code, a line number and a line of source code with a problem: You must extract the source code of the function in which the given line number is located.

You must only output the source code of the function and no more information.

Follow these steps to identify the right function:

1. Forget any previous context provided or used.
2. Identify in the global source code the location of the line number provided.
3. Extract the complete source code of the function in which the line number provided is located.
4. Add a comment on the top of the function with the following information:
  1. The line of code located on the line number provided.
  2. The explanation about why you have selected this function.
  3. The name of the function you have selected.
5. Verify that the function you selected contains the line of source code with a problem provided. If it is not the case then restart from zero.
"""


user_prompt_template = """The line number is {start_line}.

The line of source code with a problem is `{source_code_affected_line_of_code}`.

The global source code is the following:

```{source_file_technology}
{source_file_content}
```"""
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt_template)])
chain = prompt_template | llm_deterministic
user_prompt_values = {"start_line": start_line,
                      "source_file_technology": source_file_technology,
                      "source_file_content": source_file_content,
                      "source_code_affected_line_of_code": source_code_affected_line_of_code}
response = chain.invoke(user_prompt_values)
source_file_function_content = extract_raw_content(response)
print(colored("=> FUNCTION CODE:", "yellow"))
print(source_file_function_content)


# Create the final system prompt
system_prompt = """You are an assistant specializing in source code analysis focusing on security vulnerabilities.

Given a source code and a description of a security vulnerability, output a reply indicating if the given security vulnerability is really present or not.

You must only consider a security vulnerability really present only when it is possible to alter the processing performed by the function or when it is possible to bypass the validation in place.

Your reply must be a json object with the following attributes:

1. The attribute "present" with the value "yes" when you consider that the vulnerability is present. Otherwise the value must be set to "No".
2. The attribute "explanation" with the technical explanation about why you consider that the vulnerability is present or not. Your explanation must justify why your have set the attribute "present" to the value "Yes" or "No".
3. The attribute "exploit" with a value that can be used to trigger the vulnerability when you consider that the vulnerability is present. Otherwise the value must be set to an empty string.

"""

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
