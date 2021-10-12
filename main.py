import time
from functools import wraps

import bcrypt
import jwt
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer

app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:2223404egor@localhost/PetAuth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

key = 's3cr3tka'


class ProductNotExist(Exception):
    """Продукт не существует"""


class Products(db.Model):
    __tablename__ = 'Products'
    id = db.id = Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    exp_time = db.Column(db.DateTime, nullable=False)
    received_date = db.Column(db.DateTime, nullable=False)


class Users(db.Model):
    __tablename__ = 'Users'
    id = db.id = Column(Integer, primary_key=True, )
    username = db.Column(db.Text(255), nullable=False)
    password = db.Column(db.Text(255), nullable=False)
    role = db.Column(db.String(255), nullable=False, default='user')


def user_is(roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            userid = request.headers.get('Authorization')
            userid = jwt.decode(userid, key, algorithms="HS256")['id']
            role = list(db.session.query(Users.role).filter(Users.id == userid).first())[0]
            print(roles, role)
            if role not in roles:
                return jsonify(msg="You dont have permission"), 403
            return func(*args, **kwargs)

        return wrapper

    return decorator


def JWTsend(id):
    timenow = time.time() + 86400
    encoded = jwt.encode({'exp': timenow, 'id': id}, key, algorithm="HS256")
    return encoded  # jwt.decode(encoded, key, algorithms="HS256")


def auth(func):
    def check(*args, **kwargs):
        jwtoken = request.headers.get('Authorization')
        if jwtoken is None:
            return jsonify(msg="Empty auth token"), 403
        try:
            decoded = jwt.decode(jwtoken, key, algorithms="HS256")
            if decoded['exp'] < time.time():
                return jsonify(msg="Not authorized"), 401
            return func(*args, **kwargs)
        except Exception as e:
            return jsonify(msg=f"{e}"), 404

    check.__name__ = func.__name__
    return check


@app.route('/register', methods=["POST"])
def register():
    name = request.json.get('username')
    passw = request.json.get('password')
    hashpass = bcrypt.hashpw(passw.encode(), bcrypt.gensalt())
    print(passw)
    print(hashpass)
    users = db.session.query(Users.username).filter(Users.username == name).first()
    if users is None:
        data = Users(username=name, password=hashpass.decode('utf-8'))
        db.session.add(data)
        db.session.commit()
        print('юзер добавлен')
        return 'юзер добавлен'
    print('такой пользователь уже существует')
    return 'такой пользователь уже существует'


@app.route('/login', methods=["POST"])
def login():
    name = request.json.get('username')
    passw = request.json.get('password')
    users = list(db.session.query(Users.username).filter(Users.username == name).first())[0]
    hashed = db.session.query(Users.password).filter(Users.username == name).first()[0]
    id = db.session.query(Users.id).filter(Users.username == name).first()[0]
    if users == name:
        if bcrypt.checkpw(passw.encode(), bytes(hashed, 'utf-8')):
            return f'вход выполнен {name} {users} \n {JWTsend(id)}'

    else:
        return f'пользователь не найден {name} {users}'


@app.route('/products', methods=["GET"])
def get_all_products():
    prods = db.session.query(Products.id, Products.name, Products.weight, Products.exp_time,
                             Products.received_date).all()
    jsoned_prods = [{"id": i.id, "name": i.name, "weight": i.weight, "exp_time": i.exp_time,
                     "received_date": i.received_date} for i in prods]
    return jsonify(jsoned_prods), 200


@app.route('/products/<id>', methods=["GET"])
def get_product(id):
    prods = db.session.query(Products.id, Products.name, Products.weight, Products.exp_time,
                             Products.received_date).filter(Products.id == id).all()
    return jsonify(prods)


@app.route('/products', methods=["POST"])
@auth
@user_is(["moder", "admin"])
def add_product():
    name = request.json.get('name')
    weight = request.json.get('weight')
    exp_time = request.json.get('exp_time')
    received_date = request.json.get('received_date')
    try:
        data = Products(name=name, weight=weight, exp_time=exp_time, received_date=received_date)
        db.session.add(data)
        db.session.commit()
        print('товар добавлен')
        return 'товар добавлен'
    except Exception as e:
        return jsonify(msg=f"{e}"), 404


@app.route('/products/<id>', methods=["PUT"])
@auth
@user_is(["moder", "admin"])
def update_product(id):
    name = request.json.get('name')
    weight = request.json.get('weight')
    exp_time = request.json.get('exp_time')
    received_date = request.json.get('received_date')
    try:
        products = db.session.query(Products).get(id)
        if not products:
            raise ProductNotExist
        products.name = name
        products.weight = weight
        products.exp_time = exp_time
        products.received_date = received_date
        db.session.commit()
        print('товар изменен')
        return 'товар изменен'
    except ProductNotExist:
        return 'товар не существует'
    except Exception as e:
        return jsonify(msg=f"{e}"), 403


@app.route('/products/<id>', methods=["DELETE"])
@auth
@user_is(["admin"])
def delete_product(id):
    try:
        products = db.session.query(Products).get(id)
        if not products:
            raise ProductNotExist
        db.session.delete(products)
        db.session.commit()
        print('товар удален')
        return 'товар удален'
    except ProductNotExist:
        return 'товар не существует'
    except Exception as e:
        return jsonify(msg=f"{e}"), 403


if __name__ == '__main__':
    app.run()
