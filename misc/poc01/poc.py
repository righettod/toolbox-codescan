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
from langchain.prompts import ChatPromptTemplate
from langchain.agents import Tool
from langchain.agents import initialize_agent, AgentType
from langchain.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
import warnings

# As it is a POC with a single tool call then I explicitly want to use langchain.
warnings.filterwarnings(
    "ignore",
    message="LangChain agents will continue to be supported, but it is recommended for new use cases to be built with LangGraph"
)


# Constants
DEFAULT_ENCODING = "utf-8"
OLLAMA_MODEL_CODE_REASONING = "qwen2.5-coder"
OLLAMA_MODEL_CODE_REASONING_TEMPERATURE = 0.0
GITLEAKS_REPORT_FILE = "findings.json"
WEAK_PASSWORDS_LIST = ["password, azerty"]

# Execution context
INDEX_OF_TESTED_SECRET = 0  # Zero based
if len(sys.argv) == 2:
    INDEX_OF_TESTED_SECRET = int(sys.argv[1])


def is_know_weak_password(value: str) -> bool:
    """Return a boolean indicating if a string specified by the 'value' parameter is know to be a weak password."""
    return (value in WEAK_PASSWORDS_LIST)


def extract_raw_content(input):
    output = input.replace(f"```json", "")
    output = output.replace("```", "")
    output = output.strip(" \n\t\r")
    return output


def get_technology_from_filename(filename):
    if filename.endswith(".js"):
        tech = "javascript"
    elif filename.endswith(".py"):
        tech = "python"
    elif filename.endswith(".sh"):
        tech = "bash"
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

# TODO: Update the decision flow to add a step to detect if the value specified is a placeholder to a properties file.

# Create the final system prompt
system_prompt_code_reasoning = """You are an assistant specializing in secret analysis focusing on analysis if a value is a secret. Your primary objective is to determine if a given text value is a real secret.

Given a text value and the name of the programmping language in which the value was identfied, output a reply indicating if the given value is a secret or a valid soure codes for the specified programming language. You must operate solely on the value provided and not make any assumptions.

**Decision Flow:**

**Data Analysis** - Follow the steps below in sequence:

1. Identify if the provided text value is a valid source code for the provided name of programming language:
  * If yes then consider that the provided text value is not a real secret.
  * If no then move to the next step.
2. Identify if the provided text value is a **know weak password**:
  * If yes then consider that the provided text value is a real secret.
  * If no then move to the next step.
3. Identify if the provided text value is a reference to an **environment variable** from an operating system perspective:
  * If yes then consider that the provided text value is not a real secret.
  * If no then move to the next step.
4. Identify if the provided text value is a **Expression Language placeholder** from the specified programming language perspective:
  * If yes then consider that the provided text value is not a real secret.
  * If no then move to the next step.    
5. Identify if the provided text value is a word that **you know**:
  * If yes then consider that the provided text value is not a real secret.
  * If no then consider that the provided text value is a real secret.  

**Output Format:**

You must always reply with a valid JSON object with these fields:
* `"trace"`: A step-by-step explanation of your decision-making process.
* `"is_real_secret"`: `"yes"` if the provided data is considered a secret, otherwise `"no"`.
"""

# Create the final user prompt
user_prompt_template_code_reasoning = """The programming language is `{secret_file_technology}`.

The text value to analyse is `{secret_value}`.
"""

user_prompt_values = {"secret_file_technology": secret_file_technology, "secret_value": secret_value}

# Use the model to analyse the secret
# Use a deterministic behavior of the model via a temperature to zero
llm_code_reasoning = OllamaLLM(model=OLLAMA_MODEL_CODE_REASONING, temperature=OLLAMA_MODEL_CODE_REASONING_TEMPERATURE)
# Use an agent to include call to the tools
print(colored(f"=> [{OLLAMA_MODEL_CODE_REASONING}] REPLY:", "yellow"))
is_know_weak_password_tool_description = "Verify if a string specified is know to be a weak password. Return TRUE only if the string specified is know to be a weak password.\n"
is_know_weak_password_tool_description += "Parameters:\n"
is_know_weak_password_tool_description += "- value (str): The password to evaluate."
is_know_weak_password_tool = Tool(name="is_know_weak_password", func=is_know_weak_password, description=is_know_weak_password_tool_description)
system_prompt = SystemMessagePromptTemplate.from_template(system_prompt_code_reasoning)
human_prompt = HumanMessagePromptTemplate.from_template(user_prompt_template_code_reasoning)
prompt_template = ChatPromptTemplate.from_messages([system_prompt, human_prompt])
agent = initialize_agent(tools=[is_know_weak_password_tool], llm=llm_code_reasoning, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=False, handle_parsing_errors=True)
# Invoke the agent with the user prompt values
formatted_prompt = prompt_template.format(**user_prompt_values)
response = agent.invoke(formatted_prompt)
print(extract_raw_content(response["output"]))
