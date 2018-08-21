"""
Chart of api
------------
Resource            Address     Protocol    Param               Responses
-----------------------------------------------------------------
Register            /sign-up    POST        username,           200 OK
                                            password            301: Exist username

Detect similiar
of docs             /detect     POST        username,           200 OK: return similiarity
                                            password,           301: Invalid username
                                            text1,              302: Invalid password
                                            text2               3023: Out of tokens

Refill              /refill     POST        username,           200 OK
sentence                                    admin password      301: Invalid username
                                            refill amount       302: Invalid admin password


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
db = client.SimiliarityDB
Users = db["Users"]

ADMIN_PW = "admin@123"

def checkPostedData(request, api):
    data = request.get_json()

    if ("username" not in data) or (not api == "refill" and "password" not in data):
        return {
            "result": "Missing params username or password",
            "status": 301
        }
    
    if api == "detect":
        if "text1" not in data or "text2" not in data:
            return {
                "result": "Missing params text1 or text2",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "password": data["password"],
                "text1": data["text1"],
                "text2": data["text2"]
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

class Detect(Resource):
    def post(self):
        data = checkPostedData(request, "detect")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        text1 = data["text1"]
        text2 = data["text2"]

        # Verify username
        current_user = getUser(username)
        if current_user.count() == 0:
            return jsonify({
                "status": 301,
                "message": "Invalid username"
            })
        
        # Verify password
        correct_pw = verifyPw(current_user, password)
        if not correct_pw:
            return jsonify({
                "status": 301,
                "message": "Password doesn't map"
            })
        
        # Verify token
        num_tokens = countTokens(current_user)
        if num_tokens <= 0:
            return jsonify({
                "status": 303,
                "message": "You're out of tokens, please refill"
            })
        else:
            Users.update({
                "username": username
            }, {
                "$set": {
                    "tokens": num_tokens - 1
                }
            })
        
        # Calculate the edit distance
        import spacy
        nlp = spacy.load('en_core_web_sm')
        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)

        # Ratio is a number between 0 and 1 the closer to 1, 
        # the more similar text1 and text2 are
        return jsonify({
            "status": 200,
            "similiarity": ratio,
            "message": "Similarity score calculated successfully"
        })

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
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
