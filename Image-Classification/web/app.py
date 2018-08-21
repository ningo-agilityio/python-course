"""
Chart of api
------------
Resource            Address     Protocol    Param               Responses
-----------------------------------------------------------------
Register            /sign-up    POST        username,           200 OK
                                            password            301: Exist username

Classify            /classify   POST        username,           200 OK: return similiarity
                                            password,           301: Invalid username
                                            url                 302: Invalid password
                                                                303: Out of tokens

Refill              /refill     POST        username,           200 OK
sentence                                    admin password      301: Invalid username
                                            refill amount       302: Invalid admin password


"""

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy
import tensorflow as tf
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

# db is the name should be the same as folder name db
# connect app to db
client = MongoClient("mongodb://db:27017")

# Set database name
db = client.ImageRecognition
Users = db["Users"]

ADMIN_PW = "admin@123"

def checkPostedData(request, api):
    data = request.get_json()

    if ("username" not in data) or (not api == "refill" and "password" not in data):
        return {
            "result": "Missing params username or password",
            "status": 301
        }
    
    if api == "classify":
        if "url" not in data:
            return {
                "result": "Missing params url",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "password": data["password"],
                "url": data["url"]
            }
    
    if api == "refill":
        if "refill" not in data or "admin_pw" not in data:
            return {
                "result": "Missing params refill or admin_pw",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "admin_pw": data["admin_pw"],
                "refill": data["refill"]
            }
    
    return {
        "username": data["username"],
        "password": data["password"]
    }

def getUser(username):
    return Users.find({
        "username": username
    })

def verifyPw(user, password):
    hashed_pw = user[0]["password"]
    return bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw    

def countTokens(user):
    return user[0]["tokens"]   

def verifyCredential(username, password):
    error = None

    # Verify username
    current_user = getUser(username)
    if current_user.count() == 0:
        error = {
            "status": 301,
            "message": "Invalid username"
        }
    
    # Verify password
    correct_pw = verifyPw(current_user, password)
    if not correct_pw:
        error = {
            "status": 301,
            "message": "Password doesn't map"
        }
    
    # Verify token
    num_tokens = countTokens(current_user)
    if num_tokens <= 0:
        error = {
            "status": 303,
            "message": "You're out of tokens, please refill"
        }
    
    return {
        current_user: current_user,
        num_tokens: num_tokens,
        error: error
    }
    
class Signup(Resource):
    def post(self):
        data = checkPostedData(request, "sign-up")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]

        # Get current user
        current_user = getUser(username)

        # Check if exist
        if current_user.count() == 0:
            # Store data in db
            # Need to check exist user
            Users.insert({
                "username": username, 
                "password": bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt()),
                "tokens": 3
            })
        else:
            return jsonify({
                "status": 301,
                "message": "This user has already been used"
            })

        return jsonify({
            "status": 200,
            "message": "You successfully signed up for the API"
        })

class Classify(Resource):
    def post(self):
        data = checkPostedData(request, "classify")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        url = data["url"]

        current_user, num_tokens, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)

        r = requests.get(url).json()
        retJson = {}
        with open('temp.jpg', 'wb') as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                print("text file:", g)
                retJson = json.load(g)

        Users.update({
            "username": username
        }, {
            "$set": {
                "tokens": num_tokens - 1
            }
        })
        return retJson
            
class Refill(Resource):
    def post(self):
        data = checkPostedData(request, "refill")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["admin_pw"]
        refill_amount = data["refill"]

        # Verify username
        current_user = getUser(username)
        if current_user.count() == 0:
            return jsonify({
                "status": 301,
                "message": "Invalid username"
            })
        
        if not password == ADMIN_PW:
            return jsonify({
                "status": 304,
                "message": "Invalid admin password"
            })
        
        Users.update({
            "username": username
        }, {
            "$set": {
                "tokens": refill_amount + countTokens(current_user)
            }
        })

        return jsonify({
            "status": 200,
            "message": "Refilled successfully"
        })

# Register resource
api.add_resource(Signup, "/sign-up")
api.add_resource(Classify, "/classify")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
