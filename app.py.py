from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import bcrypt
import mercadopago
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)

# ✅ SDK do Mercado Pago com token direto no construtor
mp_token = os.getenv('MP_ACCESS_TOKEN')
if not mp_token:
    raise Exception("❌ MP_ACCESS_TOKEN não definido no .env")

sdk = mercadopago.SDK(mp_token)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    senha = db.Column(db.String(150))
    pagou = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        if Usuario.query.filter_by(email=email).first():
            flash('❗ Este e-mail já está cadastrado.')
            return redirect(url_for('registrar'))

        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
        usuario = Usuario(email=email, senha=senha_hash)
        db.session.add(usuario)
        db.session.commit()
        flash('✅ Cadastro realizado com sucesso!')
        return redirect(url_for('login'))
    return render_template('registrar.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario.senha):
            login_user(usuario)
            return redirect(url_for('pagamento'))
        else:
            flash('Login inválido')
    return render_template('login.html')

@app.route('/pagamento', methods=['GET', 'POST'])
@login_required
def pagamento():
    if request.method == 'POST':
        aluno = request.form.get('aluno')
        preco = 10 if aluno == 'sim' else 15

        preference_data = {
            "items": [{
                "title": "Acesso à Calculadora",
                "quantity": 1,
                "currency_id": "BRL",
                "unit_price": preco
            }],
            "back_urls": {
                "success": "http://localhost:5000/pagamento-sucesso",
                "failure": "http://localhost:5000/falhou"
            }
        }

        preference_response = sdk.preference().create(preference_data)
        print("🧾 DEBUG Mercado Pago:", preference_response)
        preference = preference_response.get("response", {})
        if 'init_point' in preference:
            return redirect(preference['init_point'])
        else:
            flash("❌ Erro ao gerar link de pagamento.")
            return redirect(url_for('pagamento'))

    return render_template('pagamento.html', preference=None)

@app.route('/pagamento-sucesso')
@login_required
def pagamento_sucesso():
    current_user.pagou = True
    db.session.commit()
    flash('✅ Pagamento confirmado com sucesso! Acesso liberado.')
    return redirect(url_for('calculadora'))

@app.route('/falhou')
@login_required
def falhou():
    flash('❌ Pagamento não concluído. Tente novamente.')
    return redirect(url_for('pagamento'))

@app.route('/calculadora')
@login_required
def calculadora():
    if not current_user.pagou:
        flash('⚠️ Acesso restrito. Realize o pagamento.')
        return redirect(url_for('pagamento'))
    return render_template('calculadora.html')

@app.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form['email']
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            token = s.dumps(email, salt='recuperar-senha')
            link = url_for('redefinir_senha', token=token, _external=True)
            msg = Message('CyberFit - Redefinir Senha', recipients=[email])
            msg.body = f'Clique no link para redefinir sua senha: {link}'
            mail.send(msg)
            flash('📧 E-mail enviado com o link para redefinir sua senha.')
            return redirect(url_for('login'))
        else:
            flash('❗ E-mail não encontrado.')
    return render_template('esqueci_senha.html')

@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    try:
        email = s.loads(token, salt='recuperar-senha', max_age=3600)
    except SignatureExpired:
        return '⏳ Link expirado.'
    except BadSignature:
        return '❌ Link inválido.'

    if request.method == 'POST':
        nova_senha = request.form['senha']
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            usuario.senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
            db.session.commit()
            flash('✅ Senha redefinida com sucesso.')
            return redirect(url_for('login'))
    return render_template('redefinir_senha.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
