from autogen_agentchat.agents import AssistantAgent, ToolAgent
from autogen_agentchat.messages import HandoffMessage

@tool(confirmation="Are you sure you want to delete this user?")
def delete_user(user_id: str) -> str:
    """Delete a user from the system."""
    return f"User {user_id} deleted."

agent = AssistantAgent(name="admin", tools=[delete_user])
