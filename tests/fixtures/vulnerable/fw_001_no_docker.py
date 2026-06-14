from autogen_agentchat.agents import AssistantAgent

code_executor_agent = AssistantAgent(
    name="coder",
    system_message="You write and execute Python code.",
    code_execution_config={"work_dir": "coding", "use_docker": False},
)
