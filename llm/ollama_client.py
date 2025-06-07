import requests

def query_llm(prompt):
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "phi",
        "prompt": prompt,
        "stream": False
    }
    response = requests.post(url, json=payload)
    return response.json()['response'] 