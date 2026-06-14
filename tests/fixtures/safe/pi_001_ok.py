import openai

client = openai.OpenAI(api_key="sk-placeholder")

system_prompt = "You are a helpful assistant."
user_input = input("Ask: ")
response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_input},
    ]
)
print(response.choices[0].message.content)
