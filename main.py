from flask import Flask , render_template
app = Flask(__name__)

@app.route('/<string:name>')
def helloworld(name):
    print(name)
    return render_template('home.html', name = name)

if __name__ == '__main__':
    app.run(debug = True , port = 2903)
    
    