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
from termcolor import colored
from langchain_ollama import OllamaLLM
from langchain.callbacks.base import BaseCallbackHandler
from langchain.prompts import ChatPromptTemplate

# Constants
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
GITLEAKS_REPORT_FILE = "findings.json"

# Execution context
INDEX_OF_TESTED_SECRET = 0  # Zero based
if len(sys.argv) == 2:
    INDEX_OF_TESTED_SECRET = int(sys.argv[1])


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


def extract_raw_content(input):
    output = input.replace(f"```json", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r")
    return output


def get_technology_from_filename(filename):
    tech = "text"
    if filename.endswith(".js"):
        tech = "javascript"
    elif filename.endswith(".py"):
        tech = "python"
    elif filename.endswith(".xml"):
        tech = "xml"
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
print(f"{msg}\n{secret_file_technology}.")
msg = colored("Text value:", "cyan")
print(f"{msg}\n{secret_value}.")
print("")

# ===============================
# CODE REASONING PHASE
# ===============================

# Create the final system prompt
system_prompt_code_reasoning = """You are an assistant specializing in secret analysis focusing on analysis if a value is a secret. Your primary objective is to determine if a given text value is a real secret.

Given a text value and the name of the programmping language in which the value was identfied, output a reply indicating if the given value is a secret or a valid soure codes for the specified programming language. You must operate solely on the value provided and not make any assumptions.

**Decision Flow:**

1. **Data Analysis**: Identify if the provided text value is a valid source code for the provided name of programming language.
2. **Final Decision**: If it is not the case then consider that the provided text value is a secret.

**Output Format:**

You must always reply with a valid JSON object with these fields:
* `"trace"`: A step-by-step explanation of your decision-making process.
* `"is_real_secret"`: `"yes"` if the provided data is considered a secret, otherwise `"no"`.
"""

# Create the final user prompt
user_prompt_template_code_reasoning = """The programming language is `{secret_file_technology}`.

The text value to analyse is `{secret_value}.`
"""

user_prompt_values = {"secret_file_technology": secret_file_technology, "secret_value": secret_value}

# Use the model to analyse the secret
# Use a deterministic behavior of the model via a temperature to zero
llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE)
prompt_template = ChatPromptTemplate.from_messages([("system", system_prompt_code_reasoning), ("human", user_prompt_template_code_reasoning)])
chain = prompt_template | llm_code_reasoning

# Invoke the chain with the user prompt values
print(colored(f"=> [{OLLAMA_MODEL_CODE_REASONING}] REPLY:", "yellow"))
prompt_printer_callback = MyPromptPrinter()
conversation_config = {"callbacks": []}
response = chain.invoke(user_prompt_values, config=conversation_config)
raw_response = extract_raw_content(response)
print(raw_response)
print("")
