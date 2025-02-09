from flask import Flask
app = Flask(__name__)

@app.route('/')
def helloworld():
    return "hello world"

if __name__ == '__main__':
    app.run(debug = True , port = 2903)
    
    