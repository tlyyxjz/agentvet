API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
import requests

headers = {"Authorization": f"Bearer {API_KEY}"}
resp = requests.get("https://api.openai.com/v1/models", headers=headers)
print(resp.json())
