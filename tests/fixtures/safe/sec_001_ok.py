import os
import requests

api_key = os.environ["OPENAI_API_KEY"]
headers = {"Authorization": f"Bearer {api_key}"}
resp = requests.get("https://api.openai.com/v1/models", headers=headers)
print(resp.json())
