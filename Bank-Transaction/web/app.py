"""
Chart of api
------------
Resource            Address     Protocol    Param               Responses
-----------------------------------------------------------------
Register            /sign-up    POST        username,           200 OK
                                            password            301: Exist username

Add                 /classify   POST        username,           200 OK
                                            password,           301: Invalid username
                                            amount              302: Invalid password

Transfer            /transfer   POST        username,           200 OK
                                            password            301: Invalid username
                                            to                  302: Invalid password
                                            amount       
                                            
Check Balance       /balance    POST        username            200 OK
                                            password            301: Invalid username
                                                                302: Invalid password

Take loan           /take-loan  POST        username            200 OK
                                            password            301: Invalid username
                                            amount              302: Invalid password

Pay loan            /pay-loan   POST        username            200 OK
                                            password            301: Invalid username
                                            amount              302: Invalid password
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
db = client.BankTransaction
Users = db["Users"]

def checkPostedData(request, api):
    data = request.get_json()

    if ("username" not in data) or (not api == "refill" and "password" not in data):
        return {
            "result": "Missing params username or password",
            "status": 301
        }
    
    if api == "add" or api == "take-loan" or api == "pay-loan":
        if "amount" not in data:
            return {
                "result": "Missing params amount",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "password": data["password"],
                "amount": data["amount"]
            }
    
    if api == "transfer":
        if "to" not in data or "amount" not in data:
            return {
                "result": "Missing params to or amount",
                "status": 301
            }
        else:
            return {
                "username": data["username"],
                "password": data["password"],
                "amount": data["amount"],
                "to": data["to"]
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
            "status": 302,
            "message": "Password doesn't map"
        }
    
    return {
        current_user: current_user,
        error: error
    }

def cashWithUser(username):
    return Users.find({"username": username})[0]["own"]

def debtWithUser(username):
    return Users.find({"username": username})[0]["debt"]

def updateAccount(username, balance):
    Users.update({
        "username": username
    }, {
        "$set": {
            "own": balance
        }
    })
def updateDebt(username, debt):
    Users.update({
        "username": username
    }, {
        "$set": {
            "debt": debt
        }
    })

BANK_TRANSACTION_FEE = 1
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
                "own": 0,
                "debt": 0
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

class Add(Resource):
    def post(self):
        data = checkPostedData(request, "add")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        money = int(data["amount"])

        # Get current user
        current_user = getUser(username)

        # Verify user
        current_user, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)
        
        if money <= 0:
             return jsonify({
                "status": 304,
                "message": "The money amount entered must be greater than 0"
            })

        cash = cashWithUser(username)
        money = money - BANK_TRANSACTION_FEE
        bank_cash = cashWithUser("BANK")

        # Charge bank transaction fee
        updateAccount("BANK", bank_cash + BANK_TRANSACTION_FEE)

        # Add money to account
        updateAccount(username, cash + money)

        return jsonify({
            "status": 200,
            "message": "Amount was added successfully to account"
        })

class Transfer(Resource):
    def post(self):
        data = checkPostedData(request, "transfer")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        money = int(data["amount"])
        to = data["to"]

        # Get current user
        current_user = getUser(username)

        # Verify user
        current_user, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)
        
        cash_from = cashWithUser(username)
        if cash_from <= 0:
            return jsonify({
                "status": 304,
                "message": "You're out of money"
            })
        
        cash_to = cashWithUser(to)
        bank_cash = cashWithUser("BANK")
        # Charge bank transaction fee
        updateAccount("BANK", bank_cash + BANK_TRANSACTION_FEE)

        # Add money from receive user
        updateAccount(to, cash_to + money - BANK_TRANSACTION_FEE)

        # Subtract money from send user
        updateAccount(username, cash_from - money)

        return jsonify({
            "status": 200,
            "message": "Amount transfer successfully"
        })

class Balance(Resource):
    def post(self):
        data = checkPostedData(request, "balance")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]

        # Get current user
        current_user = getUser(username)

        # Verify user
        current_user, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)
        
        balance = Users.find({
            "username": username
        }, {
            "password": 0,
            "_id": 0
        })[0]

        return jsonify(balance)

class TakeLoan(Resource):
    def post(self):
        data = checkPostedData(request, "take-loan")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        money = int(data["amount"])

        # Get current user
        current_user = getUser(username)

        # Verify user
        current_user, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)
        
        bank = cashWithUser("BANK")
        cash = cashWithUser(username)
        debt = debtWithUser(username)

        updateAccount(username, cash + money)
        updateAccount("BANK", bank - money)
        updateDebt(username, debt + money)

        return jsonify({
            "status": 200,
            "message": "Loan added to your account"
        })

class PayLoan(Resource):
    def post(self):
        data = checkPostedData(request, "pay-loan")
        if "status" in data:
            return jsonify(data)

        username = data["username"]
        password = data["password"]
        money = int(data["amount"])

        # Get current user
        current_user = getUser(username)

        # Verify user
        current_user, error = verifyCredential(username, password)

        if not error is None:
            return jsonify(error)
        
        bank = cashWithUser("BANK")
        cash = cashWithUser(username)
        debt = debtWithUser(username)

        if cash < money:
            return jsonify({
                "status": 303,
                "message": "Not enough cash in your account"
            })
            
        updateAccount(username, cash - money)
        updateAccount("BANK", bank + money)
        updateDebt(username, debt - money)

        return jsonify({
            "status": 200,
            "message": "You've successfully paid your load"
        })
# Register resource
api.add_resource(Signup, "/sign-up")
api.add_resource(Add, "/add")
api.add_resource(Transfer, "/transfer")
api.add_resource(Balance, "/balance")
api.add_resource(TakeLoan, "/take-loan")
api.add_resource(PayLoan, "/pay-loan")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
