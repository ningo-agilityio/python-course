from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)

# db is the name should be the same as folder name db
# connect app to db
client = MongoClient("mongodb://db:27017")
db = client.aNewDB
UserNum = db["UserNum"]
UserNum.insert({
    'num_of_users': 0
})

class Visit(Resource):
    def get(self):
        prev_num = UserNum.find()[0]['num_of_users']
        new_num = prev_num + 1
        # key of object must be string
        UserNum.update({}, {"$set": {"num_of_users": new_num}})
        return str("Hello user " + str(new_num))

@app.route('/') # 127.0.0.1:5000/
def hello_world():
    return "Hello World"

@app.route('/hi') # 127.0.0.1:5000/hi
def hi_there():
    return "Hi over there, I'm Ni Ngo"

@app.route('/bye') # 127.0.0.1:5000/bye
def bye():
    return "Bye, see you again"

@app.route('/users') # 127.0.0.1:5000/users
def get_users():
    users = {
        "name": "Lincoln",
        "age": 50,
        "phone": [
            {
                "phoneName": "Samsung S8",
                "phoneNumber": 1223535348
            },
            {
                "phoneName": "Samsung Docomo",
                "phoneNumber": 1263550505
            }
        ]
    }
    return jsonify(users)

@app.route('/add_nums', methods=['POST'])
def add_nums():
    data = request.get_json()
    if "x" not in data or "y" not in data:
        return "Miss params x or y", 305

    x = data["x"]
    y = data["y"]
    
    return jsonify({
        "z": x + y
    }), 200

def get_requests_params(request, functionName):
    data = request.get_json()

    if "x" not in data or "y" not in data:
        return {
            "result": "Missing params x or y",
            "status": 301
        }
    
    x = int(data["x"])
    y = int(data["y"])

    if functionName == 'divide' and y == 0:
        return {
            "result": "y can not be zero",
            "status": 302
        }

    return {
        "x": x,
        "y": y
    }

# DEFINE +, -, *, / api resources
class Add(Resource):
    def post(self):
        params = get_requests_params(request, 'add')
        
        if "status" in params:
            return jsonify(params)

        return jsonify({
            "result": params["x"] + params["y"],
            "status": 200
        })

class Subtract(Resource):
    def post(self):
        params = get_requests_params(request, 'subtract')
        
        if "status" in params:
            return jsonify(params)

        return jsonify({
            "result": params["x"] - params["y"],
            "status": 200
        })

class Divide(Resource):
    def post(self):
        params = get_requests_params(request, 'divide')
        
        if "status" in params:
            return jsonify(params)

        return jsonify({
            "result": (params["x"] * 1.0) / params["y"],
            "status": 200
        })

class Multiply(Resource):
    def post(self):
        params = get_requests_params(request, 'multiply')
        
        if "status" in params:
            return jsonify(params)

        return jsonify({
            "result": params["x"] * params["y"],
            "status": 200
        })

api.add_resource(Add, '/add')
api.add_resource(Subtract, '/subtract')
api.add_resource(Divide, '/divide')
api.add_resource(Multiply, '/multiply')
api.add_resource(Visit, '/track-user')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)