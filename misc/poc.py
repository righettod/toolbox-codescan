"""
Code to test the idea and prompts.

Python dependencies:
    pip install langchain langchain-community langchain-ollama

Ollama dependencies
    ollama pull qwen2.5-coder:latest
    ollama run qwen2.5-coder:latest
"""
import json
import xml.etree.ElementTree as ET
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate

# Constants
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL = "qwen2.5-coder"
CWE_XML_REFERENTIAL = "cwec_v4.17.xml"
CWE_XML_REFERENTIAL_NAMESPACES = {"cwe": "http://cwe.mitre.org/cwe-7"}
VULNERABLE_CODEBASE_FOLDER = "vulnerable-codebase/"
INDEX_OF_TESTED_VULNERABILITY = 2

# Load the SemGrep findings
with open("findings.json", mode="r", encoding=DEFAULT_ENCODING) as f:
    vulnerabilities = json.load(f)

# Initialize the Ollama model
llm = OllamaLLM(model=OLLAMA_MODEL)

# Select one vulnerability for the POC
vulnerability = vulnerabilities["results"][INDEX_OF_TESTED_VULNERABILITY]

# Load the information of the vulnerability that
# will be used for user prompt
source_file_path = VULNERABLE_CODEBASE_FOLDER + vulnerability["path"]
source_file_technology = "java"
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


# Create the system prompt
system_prompt = """You are an AI assistant specializing in code analysis focusing on security vulnerabillties.

Given a source code, output a reply indicating if the given security vulnerability is really present or not.

Your reply will be a json object where you will set "Yes" into the json attribute "present" if the vulnerability is really present and "No" if the vulnerability is not present.

You will add the technical reason that justify your decision into the json attribute "explanation".

When referring to specific lines, use line numbers where possible."""

# Create the user prompt
user_prompt_template = """This security vulnerability was identified in the given source code:
{vulnerability_description}

The type of security vulnerability is the following:
{cwe_description}

The vulnerability was found in the given source code starting on line {start_line} in column {start_column} and ending on line {end_line} in column {end_column}.

This is the source code in which the vulnerability was identified:
```{source_file_technology}
{source_file_content}
```"""
user_prompt_values = {"vulnerability_description": vulnerability_description,
                      "cwe_description": cwe_description,
                      "start_line": start_line, "start_column": start_column, "end_line": end_line, "end_column": end_column,
                      "source_file_technology": source_file_technology,
                      "source_file_content": source_file_content}

# Create the prompts templated
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", user_prompt_template)])
chain = prompt_template | llm

# Invoke the chain with the user prompt values
response = chain.invoke(user_prompt_values)
print(response)
