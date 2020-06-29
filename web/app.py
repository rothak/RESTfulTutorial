from flask import Flask, jsonify, request  # Don't confuse request with requests further below!
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
# import numpy
# import tensorflow as tf
import requests  # handles retrieving data via URLs
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db["Users"]


class Register(Resource):
    def post(self):
        posteddata = request.get_json()

        username = posteddata["username"]  # accessing the data as with a usual dictionary in Python
        password = posteddata["password"]

        if user_exist(username):
            # use the User_exist function to check whether registered username already exists in db. If so, return error
            return jsonify(generatereturndictionary(301, "Invalid Username"))

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,  # storing the hashed_pw, not the clear text 'password'
            "Tokens": 5  # opening a starting balance of 5 tokens
        })

        num_tokens = count_tokens(username)  # Balance of tokens

        retjson = {
            'Message': f"Successfully signed up for the API. You have {num_tokens} tokens",
            'Status': 200
        }
        return jsonify(retjson)


def user_exist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


def count_tokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


def generatereturndictionary(status, msg):
    retjson = {
        "status": status,
        "msg": msg
    }
    return retjson


def verify_pw(username, password):
    if not user_exist(username):  # no point in checking pw if already the username is non-existing
        return False
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]  # to get the first user in the list and its pw
    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def verify_credentials(username, password):
    if not user_exist(username):
        return generatereturndictionary(301, "Invalid Username"), True

    correct_pw = verify_pw(username, password)
    if not correct_pw:
        return generatereturndictionary(302, "Invalid Password"), True

    return None, False


class Classify(Resource):
    def post(self):
        posteddata = request.get_json()

        username = posteddata["username"]  # accessing the data as with a usual dictionary in Python
        password = posteddata["password"]
        url = posteddata["url"]

        retjson, error = verify_credentials(username, password)
        if error:
            return jsonify(retjson)

        current_tokens = count_tokens(username)  # Balance of tokens
        if current_tokens <= 0:
            return jsonify(generatereturndictionary(303, "Out of Tokens"))

        # Serve image
        r = requests.get(url)   # retrieves an image from the URL
        ret_json = {}
        with open('temp.jpg', 'wb') as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt") as f:
                ret_json = json.load(f)

        current_tokens = count_tokens(username)
        users.update({
            "Username": username
        }, {
            "$set": {"Tokens": current_tokens - 1
                     }
        })
        return ret_json


class Refill(Resource):
    def post(self):
        posteddata = request.get_json()

        password = posteddata["admin_pw"]  # admin password
        username = posteddata["username"]  # end user username
        refill_amount = posteddata["refill"]

        # check the target username for refill exists
        if not user_exist(username):
            return jsonify(generatereturndictionary(301, "Invalid Username"))

        # checks the administrator password is correct (Note: ensure admin user is registered in db first)
        correct_pw = verify_pw("administrator", password)
        if not correct_pw:
            return jsonify(generatereturndictionary(304, "Invalid Admin Password"))

        # Now we can refill the user's tokens balance
        current_tokens = count_tokens(username)
        users.update({
            "Username": username
        },
            {
                "$set": {"Tokens": current_tokens + refill_amount}

            }
        )
        balance = count_tokens(username)
        retjson = {
            "status": 200,
            "msg": f"Token top-up complete. You now have {balance} tokens in your balance"
        }
        return jsonify(retjson)


api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
