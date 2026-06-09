from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash  # encripta contraseñas

app = Flask(__name__)
app.config["SECRET_KEY"] = "clave-secreta-123"          # necesario para sesiones y mensajes flash
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///usuarios.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
@app.route("/")                              # ruta raíz — cuando alguien entra sin ruta específica
def index():
    return redirect(url_for("login"))        # redirige automáticamente al login
# === configuración de flask-login ===
login_manager = LoginManager(app)                        # inicializa el manejador de sesiones
login_manager.login_view = "login"                       # si no hay sesión, redirige a /login

# === MODELO DE USUARIO ===
# UserMixin agrega métodos que flask-login necesita: is_authenticated, is_active, etc.
class Usuario(db.Model, UserMixin):
    id         = db.Column(db.Integer, primary_key=True)
    nombre     = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)  # único, no se repite
    contrasena = db.Column(db.String(200), nullable=False)               # guardará el hash, no texto plano

# flask-login necesita esta función para saber cómo cargar un usuario por su id
@login_manager.user_loader
def cargar_usuario(user_id):
    return Usuario.query.get(int(user_id))               # busca el usuario en la base de datos
# === RUTA: registro de usuario nuevo ===
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre     = request.form["nombre"]
        email      = request.form["email"]
        contrasena = request.form["contrasena"]

        # verifica si el email ya existe en la base de datos
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash("Ese email ya está registrado.")        # flash envía un mensaje temporal al HTML
            return redirect(url_for("registro"))

        # encripta la contraseña antes de guardarla — nunca se guarda en texto plano
        hash_contrasena = generate_password_hash(contrasena)

        nuevo_usuario = Usuario(
            nombre     = nombre,
            email      = email,
            contrasena = hash_contrasena                  # guarda el hash, no la contraseña original
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash("Cuenta creada correctamente. Inicia sesión.")
        return redirect(url_for("login"))

    return render_template("registro.html")


# === RUTA: inicio de sesión ===
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email      = request.form["email"]
        contrasena = request.form["contrasena"]

        usuario = Usuario.query.filter_by(email=email).first()  # busca el usuario por email

        # check_password_hash compara la contraseña ingresada con el hash guardado
        if not usuario or not check_password_hash(usuario.contrasena, contrasena):
            flash("Email o contraseña incorrectos.")
            return redirect(url_for("login"))

        login_user(usuario)                               # guarda la sesión del usuario
        return redirect(url_for("inicio"))

    return render_template("login.html")


# === RUTA: página principal protegida ===
@app.route("/inicio")
@login_required                                           # solo accesible si hay sesión activa
def inicio():
    return render_template("inicio.html")                 # current_user tiene los datos del usuario


# === RUTA: cerrar sesión ===
@app.route("/logout")
@login_required
def logout():
    logout_user()                                         # borra la sesión
    flash("Sesión cerrada correctamente.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()                                   # crea las tablas si no existen
    app.run(debug=True)