#pip install requests
import requests
import json 

def buscar_dados():
    request = requests.get("http://localhost:3002/api/todo")
    todos = json.loads(request.content)
    print(todos)
    print(todos[0]['titulo'])

if __name__ == '__main__':
    buscar_dados()

