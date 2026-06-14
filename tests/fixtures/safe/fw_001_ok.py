from autogen_ext.code_executors.docker import DockerCommandLineCodeExecutor
from autogen_agentchat.agents import AssistantAgent

executor = DockerCommandLineCodeExecutor()
code_executor_agent = AssistantAgent(
    name="coder",
    code_executor=executor,
    use_docker=True,
)
