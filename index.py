import json
import random
import hashlib
import mysql.connector
import base64
import shutil
import os
import bcrypt  # VUL-002: reemplaza md5 por bcrypt
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, get, request, static_file


def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson


def getToken():
    tiempo = datetime.now().timestamp()
    numero = random.random()
    cadena = str(tiempo) + str(numero)
    numero2 = random.random()
    m = hashlib.sha1()
    m.update(cadena.encode())
    P = m.hexdigest()
    m = hashlib.md5()
    m.update(cadena.encode())
    Q = m.hexdigest()
    return f"{P[:20]}{Q[20:]}"


@get('/')
def index():
    return {"status": "ok", "server": "insecure-webapi", "version": "1.0"}


@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}
    R = False
    try:
        with db.cursor() as cursor:
            # VUL-002: bcrypt en lugar de md5 para hashear la contraseña
            hashed = bcrypt.hashpw(request.json["password"].encode(), bcrypt.gensalt()).decode()
            # VUL-001: consulta parametrizada para evitar SQL Injection
            cursor.execute(
                'INSERT INTO Usuario VALUES(null, %s, %s, %s)',
                (request.json["uname"], request.json["email"], hashed)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e)
        return {"R": -2}
    return {"R": 0, "D": R}


@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}
    R = False
    try:
        with db.cursor() as cursor:
            # VUL-001: consulta parametrizada para evitar SQL Injection
            # VUL-002: se obtiene el hash para verificarlo con bcrypt
            cursor.execute(
                'SELECT id, password FROM Usuario WHERE uname = %s',
                (request.json["uname"],)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -3}

    # VUL-002: verificar contraseña con bcrypt en lugar de md5
    if not bcrypt.checkpw(request.json["password"].encode(), R[0][1].encode()):
        db.close()
        return {"R": -3}

    T = getToken()
    with open("/tmp/log", "a") as log:
        log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
        log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')

    try:
        with db.cursor() as cursor:
            # VUL-001: consultas parametrizadas para evitar SQL Injection
            cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario = %s', (R[0][0],))
            cursor.execute('INSERT INTO AccesoToken VALUES(%s, %s, now())', (R[0][0], T))
            db.commit()
            db.close()
            return {"R": 0, "D": T}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -4}


@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()

    if not request.json:
        return {"R": -1}
    R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
    if not R:
        return {"R": -1}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    TKN = request.json['token']
    R = False
    try:
        with db.cursor() as cursor:
            # VUL-001: consulta parametrizada para evitar SQL Injection
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    id_Usuario = R[0][0]
    with open(f'tmp/{id_Usuario}', "wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))

    try:
        with db.cursor() as cursor:
            # VUL-001: consultas parametrizadas para evitar SQL Injection
            cursor.execute(
                'INSERT INTO Imagen VALUES(null, %s, "img/", %s)',
                (request.json["name"], id_Usuario)
            )
            cursor.execute(
                'SELECT MAX(id) as idImagen FROM Imagen WHERE id_Usuario = %s',
                (id_Usuario,)
            )
            R = cursor.fetchall()
            idImagen = R[0][0]
            nueva_ruta = f'img/{idImagen}.{request.json["ext"]}'
            cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s', (nueva_ruta, idImagen))
            db.commit()
            shutil.move(f'tmp/{id_Usuario}', nueva_ruta)
            return {"R": 0, "D": idImagen}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3}


@post('/Descargar')
def Descargar():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )
    if not request.json:
        return {"R": -1}
    R = 'token' in request.json and 'id' in request.json
    if not R:
        return {"R": -1}

    TKN = request.json['token']
    idImagen = request.json['id']

    R = False
    try:
        with db.cursor() as cursor:
            # VUL-001: consulta parametrizada para evitar SQL Injection
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        return {"R": -2}

    id_Usuario_token = R[0][0]

    try:
        with db.cursor() as cursor:
            # VUL-003: verificar que la imagen pertenece al usuario autenticado
            cursor.execute(
                'SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s',
                (idImagen, id_Usuario_token)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3}

    if not R:
        # VUL-003: si la imagen no pertenece al usuario, denegar acceso
        return {"R": -3}

    return static_file(R[0][1], Path(".").resolve())


if __name__ == '__main__':
    run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), debug=False)