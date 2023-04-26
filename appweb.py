from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from pymongo import MongoClient
import datetime
import hashlib


client = MongoClient("mongodb://localhost:27017")
db = client.infoUsers
users_collection = db.users
login_collection = db.user_login

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "prioridad-el-acceso-al-usuario"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=180)

jwt = JWTManager(app)

def hide_sensitive_info(value):
    return "#" * (len(value) - 4) + value[-4:]

def get_user_info(user):
    return {
        'id': user['id'],
        'user_name': user['user_name'],
        'auto': user['auto'],
        'credit_card_num': hide_sensitive_info(user['credit_card_num']),
        'cuenta_numero': hide_sensitive_info(user['cuenta_numero'])
    }

@app.route("/dashboard", methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify(message="Bienvenido! Información de clientes", logged_in_as=current_user), 200


@app.route("/infor_cc/<uid>", methods=['GET'])
@jwt_required()
def infor_cc(uid):
    try:
        user = users_collection.find_one({"id": uid})
        if user:
            return jsonify(user_info=[get_user_info(user)]), 201
        else:
            return jsonify(message="Usuario no encontrado"), 404
    except Exception as e:
        return jsonify(message="Error en el servidor", info=str(e)), 500


@app.post("/register")
def register():
    
    email = request.form["email"]
    test = login_collection.find_one({"email": email})
    if test:
        return jsonify(message="El usuario ya existe"), 409
    else:
        first_name = request.form["Primer_nombre"]
        last_name = request.form["Apellido"]
        password = hashlib.sha256(request.form["Contraseña"].encode()).hexdigest()
        user_info = dict(first_name=first_name,last_name=last_name, email=email, password=password)
        login_collection.insert_one(user_info)
        return jsonify(message="Usuario creado exitosamente!"), 201


@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        email = request.json["email"]
        password = request.json["contraseña"]
    else:
        email = request.form["email"]
        password = request.form["contraseña"]

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = login_collection.find_one({"email": email, "password": hashed_password})
    if user:
        access_token = create_access_token(identity=email)
        return jsonify(message="Inicio de sesión exitoso!", access_token=access_token), 200
    else:
        return jsonify(message="Correo electrónico o contraseña incorrectos"), 401


if __name__ == '__main__':
    app.run(host="localhost", debug=True)
