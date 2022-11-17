import requests


session = requests.session()
session.proxies = {
    'http': '127.0.0.1:9999',
    'https': '127.0.0.1:9999',
}

print(session.get('http://example.com/').content)
print(session.get('https://example.com/').content)
