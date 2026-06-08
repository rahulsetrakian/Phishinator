import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("OPENROUTER_API_KEY")

response = requests.post(
  url="https://openrouter.ai/api/v1/chat/completions",
  headers={
    "Authorization": f"Bearer {api_key}",
  },
  data=json.dumps({
    "model": "nvidia/nemotron-3-super-120b-a12b:free",
    "messages": [
      {
        "role": "user",
        "content": "Only respond with a single word, either 'phishing' or 'legitimate'. Analyze the following email content and determine if it is a phishing attempt or a legitimate email: 'Dear User, Your account has been compromised. Please click the link below to reset your password: http://malicious-link.com. Best regards, Support Team'"
      }
    ]
  })
)

print(response.json())