import json
import requests
import pymongo
from pymongo import MongoClient, InsertOne
from pprint import pprint


endpoint_url = "https://62433a7fd126926d0c5d296b.mockapi.io/api/v1/usuarios"
obtener = requests.get(endpoint_url)
data = obtener.json()
cliente = pymongo.MongoClient("mongodb://localhost:27017")
bd = cliente.infoUsers
collection = bd.users
requesting = []
#Empleando la variable collection para obtener los datos del get
collection.insert_many(data)
for registros in collection.find():
    print(registros)