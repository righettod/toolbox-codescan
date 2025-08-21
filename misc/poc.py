"""
Code to test the idea and prompts.

Python dependencies:
    pip install langchain langchain-community langchain-ollama termcolor

Ollama dependencies:
    See README.md file for models setup.
"""
import json
import sys
import re
import uuid
import xml.etree.ElementTree as ET
from termcolor import colored
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_community.chat_message_histories import ChatMessageHistory
from langchain_core.chat_history import BaseChatMessageHistory
from langchain.callbacks.base import BaseCallbackHandler

# Constants
USE_CONVERSATION_WITH_HISTORY_APPROACH = False
SANDBOX_TECHNOLOGY = "python"
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL_CODE_EXTRACTION = "qwen2.5-coder"
OLLAMA_MODEL_CODE_EXTRACTION_TEMPERATURE = 0.0
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
CWE_XML_REFERENTIAL = "cwec_v4.17.xml"
CWE_XML_REFERENTIAL_NAMESPACES = {"cwe": "http://cwe.mitre.org/cwe-7"}
VULNERABLE_CODEBASE_FOLDER = f"vulnerable-codebase/{SANDBOX_TECHNOLOGY}/"

# Execution context
CHAT_HISTORY_STORE = {}
INDEX_OF_TESTED_VULNERABILITY = 0  # Zero based
if len(sys.argv) == 2:
    INDEX_OF_TESTED_VULNERABILITY = int(sys.argv[1])
if len(sys.argv) == 3:
    INDEX_OF_TESTED_VULNERABILITY = int(sys.argv[1])
    SANDBOX_TECHNOLOGY = str(sys.argv[2]).lower().strip()
    VULNERABLE_CODEBASE_FOLDER = f"vulnerable-codebase/{SANDBOX_TECHNOLOGY}/"


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


def extract_raw_content(input, code_marker=SANDBOX_TECHNOLOGY):
    output = input.replace(f"```{code_marker}", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r")
    return output


def get_session_history(session_id: str) -> BaseChatMessageHistory:
    """A function that returns a BaseChatMessageHistory instance for a given session ID."""
    if session_id not in CHAT_HISTORY_STORE:
        CHAT_HISTORY_STORE[session_id] = ChatMessageHistory()
    return CHAT_HISTORY_STORE[session_id]


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

# ===============================
# CODE EXTRACTION PHASE
# ===============================

# Use the model to extract the code of the function (or method) containing the range of code specified containing the vulnerability
# Use a deterministic behavior of the model via a temperature to zero
llm_code_extraction = OllamaLLM(model=OLLAMA_MODEL_CODE_EXTRACTION, temperature=OLLAMA_MODEL_CODE_EXTRACTION_TEMPERATURE)
system_prompt_code_extraction = """You are an assistant specialized in extracting a function from a source code.

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

user_prompt_template_code_extraction = """The line number is {start_line}.

The line of source code with a problem is `{source_code_affected_line_of_code}`.

The global source code is the following:

```{source_file_technology}
{source_file_content}
```"""
print(colored(f"=> [{OLLAMA_MODEL_CODE_EXTRACTION}] FUNCTION CODE EXTRACTED:", "yellow"))
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt_code_extraction), ("human", user_prompt_template_code_extraction)])
chain = prompt_template | llm_code_extraction
user_prompt_values = {"start_line": start_line,
                      "source_file_technology": source_file_technology,
                      "source_file_content": source_file_content,
                      "source_code_affected_line_of_code": source_code_affected_line_of_code}
response = chain.invoke(user_prompt_values)
source_file_function_content = extract_raw_content(response)
print(source_file_function_content)
print("")

# ===============================
# CODE REASONING PHASE
# ===============================

# Create the final system prompt
system_prompt_code_reasoning = """You are an assistant specializing in source code analysis focusing on security vulnerabilities. Your primary objective is to determine if a given security vulnerability is truly present and exploitable within a provided source code.

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

# Use a chain with no history with single system and user prompts to see the result given by the model in one shot
if not USE_CONVERSATION_WITH_HISTORY_APPROACH:
    # Create the final user prompt
    user_prompt_template_code_reasoning = """This security vulnerability was identified in the given source code:
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

    user_prompt_values = {"vulnerability_description": vulnerability_description,
                          "cwe_description": cwe_description,
                          "source_file_technology": source_file_technology,
                          "source_file_function_content": source_file_function_content,
                          "source_code_affected_line_of_code": source_code_affected_line_of_code}

    # Use the model to analyse the vulnerability against the code snippet (function/method)
    # Use a deterministic behavior of the model via a temperature to zero
    llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE)
    prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt_code_reasoning), ("human", user_prompt_template_code_reasoning)])
    chain = prompt_template | llm_code_reasoning

    # Invoke the chain with the user prompt values
    print(colored(f"=> [{OLLAMA_MODEL_CODE_REASONING}] REPLY USING CONVERSATION WITHOUT HISTORY:", "yellow"))
    prompt_printer_callback = MyPromptPrinter()
    conversation_config = {"callbacks": []}
    response = chain.invoke(user_prompt_values, config=conversation_config)
    raw_response = extract_raw_content(response, "json")
    print(raw_response)
    print("")

# Use now a chain with an history with adaptive user prompt to see if the model increase globally its accuracy across the different chat occurences
if USE_CONVERSATION_WITH_HISTORY_APPROACH:
    # Use a deterministic behavior of the model via a temperature to zero
    llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE)
    prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt_code_reasoning), MessagesPlaceholder("history"), ("human", "{input}")])
    chain = prompt_template | llm_code_reasoning
    chain_with_history = RunnableWithMessageHistory(runnable=chain, get_session_history=get_session_history, input_messages_key="input", history_messages_key="history")

    user_prompt_raw_code_reasoning = f"""This security vulnerability was identified in the given source code:
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

    prompt_printer_callback = MyPromptPrinter()
    conversation_config = {"callbacks": [], "configurable": {"session_id": str(uuid.uuid4())}}
    print(colored(f"=> [{OLLAMA_MODEL_CODE_REASONING}] REPLY USING CONVERSATION WITH HISTORY:", "yellow"))
    # ROUND 0: Initial question.
    # ROUND 1: Challenge the response provided.
    # ROUND 2: Challenge the justification provided.
    # ROUND 3: Ask to give a final answer that is YES ou NO about the presence of the vulnerability.
    for round in range(4):
        if round == 0:
            user_prompt_input = user_prompt_raw_code_reasoning
        elif round == 1:
            user_prompt_input = "Justify your decision with **technical material and proof** from a security perspective!"
        elif round == 2:
            # user_prompt_input = f"Are you sure about your understanding of the validation or sanitization in place for the code according to the technology {source_file_technology}?"
            user_prompt_input = f"Are you sure that your analysis is consistent according to the specificities of the technology {source_file_technology}?"
        else:
            user_prompt_input = "Give me a final reply represented by 'yes' if you consider that the vulnerability is present otherwise reply 'no' if you consider that the vulnerability is not present."
            user_prompt_input += "\nYou must only reply 'yes' or 'no' and no more information."
        response = chain_with_history.invoke({"input": user_prompt_input}, config=conversation_config)
        print(colored(f"\n[ROUND {round}]", "light_cyan"))
        print(response)
        print("======")
