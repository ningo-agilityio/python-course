"""
Registration of a user 0 tokens
Each user gets 10 tokens
Store a sentence on our db for 1 token
Retrieves his stored sentence on our db for 1 token
"""

"""
Chart of api
------------
Resource    Address     Protocol    Param               Responses
-----------------------------------------------------------------
Register    /sign-up    POST        username,           200 OK
                                    password

Store
sentence    /store      POST        username,           200 OK
                                    password,           301: out of tokens
                                    sentence            302: Invalid username, password

Retrieve    /get        GET         username,           200 OK
sentence                            password            301: out of tokens
                                                        302: Invalid username, password
"""

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

# db is the name should be the same as folder name db
# connect app to db
client = MongoClient("mongodb://db:27017")

# Set database name
db = client.SentencesDatabase
Users = db["Users"]

def checkPostedData(request, api):
    data = request.get_json()

    if ("username" not in data) or ("password" not in data):
        return {
            "result": "Missing params username or password",
            "status": 301
        }
    
    if api == "store":
        if "sentence" not in data:
            return {
                "result": "Missing params sentence",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "password": data["password"],
                "sentence": data["sentence"]
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
                "sentences": "",
                "tokens": 6
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

class Store(Resource):
    def post(self):
        data = checkPostedData(request, "store")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        sentence = data["sentence"]

        # Get current user
        current_user = getUser(username)

        if current_user.count() > 0:
            # Verify username and password
            correct_pw = verifyPw(current_user, password)

            if not correct_pw:
                return jsonify({
                    "status": 302,
                    "message": "Your username or password doesn't match"
                })

            # Verify user has enough tokens
            num_tokens = countTokens(current_user)
            if num_tokens <= 0:
                return jsonify({
                    "status": 301,
                    "message": "Tokens are out of date for this user"
                })

            # Store the sentence
            Users.update({
                "username": username
            }, 
            {
                "$set": {
                    "sentence": sentence,
                    "tokens": num_tokens - 1
                }
            })

            return jsonify({
                "status": 200,
                "message": "Your sentence was saved successfully"
            })
        else:
            return jsonify({
                "status": 302,
                "message": "Your username or password doesn't match"
            })

class Sentence(Resource):
    def post(self):
        data = checkPostedData(request, "sentence")
        if "status" in data:
            return jsonify(data)
        
        username = data["username"]
        password = data["password"]

        # Get current user
        current_user = getUser(username)
        if current_user.count() > 0:
            # Verify username and password
            correct_pw = verifyPw(current_user, password)
            if not correct_pw:
                return jsonify({
                "status": 302,
                "message": "Password doesn't match"
            })
        
            # Verify user has enough tokens
            num_tokens = countTokens(current_user)
            if num_tokens <= 0:
                return jsonify({
                    "status": 301,
                    "message": "Tokens are out of date for this user"
                })

            # Store the sentence
            Users.update({
                "username": username
            }, 
            {
                "$set": {
                    "tokens": num_tokens - 1
                }
            })

            return jsonify({
                "status": 200,
                "message": getUser(username)[0]["sentence"]
            })
        else:
            return jsonify({
                "status": 302,
                "message": "Your username or password doesn't match"
            })

# Register resource
api.add_resource(Signup, "/sign-up")
api.add_resource(Store, "/store")
api.add_resource(Sentence, "/sentence")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
