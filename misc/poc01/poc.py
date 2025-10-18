"""
Code to test the idea and prompts.

Python dependencies:
    pip install langchain langchain-community langchain-ollama termcolor

Ollama dependencies:
    See README.md file for models setup.
"""
import json
import sys
from pathlib import Path
from termcolor import colored
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
import warnings

# As it is a POC with a single tool call then I explicitly want to use langchain.
warnings.filterwarnings(
    "ignore",
    message="LangChain agents will continue to be supported, but it is recommended for new use cases to be built with LangGraph"
)


# Constants
VERBOSE_AGENT_MODE = True
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
OLLAMA_MODEL_RESPONSE_TIMEOUT_IN_SECONDS = 60
GITLEAKS_REPORT_FILE = "findings.json"
WEAK_PASSWORDS_LIST = ["password", "azerty"]

# Execution context
INDEX_OF_TESTED_SECRET = 0  # Zero based
if len(sys.argv) == 2:
    INDEX_OF_TESTED_SECRET = int(sys.argv[1])


def is_know_weak_password(value: str) -> str:
    if value in WEAK_PASSWORDS_LIST:
        return f"YES — '{value}' **IS ** a known weak password."
    else:
        return f"NO — '{value}' **IS NOT** a known weak password."


def extract_raw_content(input):
    output = input.replace(f"```json", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r*")
    return output


def get_technology_from_filename(filename):
    if filename.endswith(".js"):
        tech = "javascript"
    elif filename.endswith(".py"):
        tech = "python"
    elif filename.endswith(".sh"):
        tech = "bash"
    elif filename.endswith(".ps1"):
        tech = "powershell"
    elif filename.endswith(".txt") or filename.endswith(".pem"):
        tech = "raw text"
    else:
        tech = Path(filename).suffix.strip(".")
    return tech


# Load the GitLeaks findings
with open(f"findings.json", mode="r", encoding=DEFAULT_ENCODING) as f:
    secrets = json.load(f)

# Select one secret for the POC
secret = secrets[INDEX_OF_TESTED_SECRET]

# Load the information of the secret that will be used for the user prompt
secret_value = secret["Secret"]
secret_file_technology = get_technology_from_filename(secret["File"])
print(colored("=> SECRETS COUNT :", "yellow"))
print(len(secrets))
print("")
print(colored("=> SECRET:", "yellow"))
msg = colored("Programming language:", "cyan")
print(f"{msg}\n{secret_file_technology}")
msg = colored("Text value:", "cyan")
print(f"{msg}\n{secret_value}")
print("")

# ===============================
# CODE REASONING PHASE
# ===============================

# Create the final system prompt
system_prompt_code_reasoning = """You are an assistant specializing in secret analysis focusing on analysis if a value is a secret. Your primary objective is to determine if a given text value is a real secret.

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

# Create the final user prompt
user_prompt_template_code_reasoning = """The programming language is `{secret_file_technology}`.

The text value to analyse is `{secret_value}`.

Observation from weak password tool: `{weak_password_check}`.
"""

user_prompt_values = {"secret_file_technology": secret_file_technology, "secret_value": secret_value, "weak_password_check": is_know_weak_password(secret_value)}

# Use the model to analyse the secret
# Use a deterministic behavior of the model via a temperature to zero
llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE, timeout=OLLAMA_MODEL_RESPONSE_TIMEOUT_IN_SECONDS)
system_prompt = SystemMessagePromptTemplate.from_template(system_prompt_code_reasoning)
human_prompt = HumanMessagePromptTemplate.from_template(user_prompt_template_code_reasoning)
prompt_template = ChatPromptTemplate.from_messages([system_prompt, human_prompt])
final_prompt = prompt_template.format(**user_prompt_values)
print(colored(f"=> [{OLLAMA_MODEL_CODE_REASONING}] REPLY:", "yellow"))
response = llm_code_reasoning.invoke(final_prompt)
print(extract_raw_content(response))
