from pymongo.mongo_client import MongoClient
from pymongo import ASCENDING
from bson.objectid import ObjectId

class Mongo:
    def __init__(self, url) -> None:
        self.client = MongoClient(url)
        self.db = self.client["xorpass"]
        self.init_indexes()

    def init_indexes(self):
        try:
            self.db["users"].create_index([("email", ASCENDING)], unique=True)
            self.db["passwords"].create_index([("owner_id", ASCENDING)])
        except Exception as e:
            pass

    def add_user(self, password, email, public_key, private_key):
        self.db["users"].insert_one({
            "email": email,
            "password": password,
            "public_key": public_key,
            "private_key": private_key
        })

    def get_user(self, email):
        return self.db["users"].find_one({"email": email})

    def add_data(self, website, email, password, owner_id, difficulty):
        self.db["passwords"].insert_one({
            "website": website,
            "email": email,
            "password": password,
            "owner_id": owner_id,
            "difficulty": difficulty
        })

    def get_data(self, owner_id):
        datas = []
        for x in self.db["passwords"].find({"owner_id": owner_id}):
            datas.append(x)
        return datas

    def get_by_email(self, email):
        return self.db["passwords"].find_one({"email": email})

    def update_user(self, email, data):
        self.db["users"].update_one({"email": email}, {"$set": data})

    def get_by_id(self, id):
        try:
            return self.db["passwords"].find_one({"_id": ObjectId(id)})
        except Exception:
            return None

    def update_by_id(self, id, data):
        try:
            self.db["passwords"].update_one({"_id": ObjectId(id)}, {"$set": data})
        except Exception:
            pass

    def delete_user(self, email):
        self.db["users"].delete_one({"email": email})

    def delete_data(self, id):
        try:
            self.db["passwords"].delete_one({"_id": ObjectId(id)})
        except Exception:
            pass
