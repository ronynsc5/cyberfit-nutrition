from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_migrate import Migrate, upgrade
import bcrypt
import mercadopago
import os
import re
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
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)
sdk = mercadopago.SDK(os.getenv('MP_ACCESS_TOKEN'))
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 👤 Modelo atualizado com o campo nome e premium
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True)
    senha = db.Column(db.String(150))
    premium = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('❗ E-mail inválido.')
            return redirect(url_for('registrar'))

        if Usuario.query.filter_by(email=email).first():
            flash('❗ Este e-mail já está cadastrado.')
            return redirect(url_for('registrar'))

        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        usuario = Usuario(nome=nome, email=email, senha=senha_hash)
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
        if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario.senha.encode('utf-8')):
            login_user(usuario)
            return redirect(url_for('calculadora') if usuario.premium else url_for('pagamento'))
        else:
            flash('❌ Login inválido')
    return render_template('login.html')

@app.route('/pagamento', methods=['GET', 'POST'])
@login_required
def pagamento():
    if current_user.premium:
        return redirect(url_for('calculadora'))

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
            "payer": {
                "email": current_user.email
            },
            "back_urls": {
                "success": url_for('liberando_acesso', _external=True),
                "failure": url_for('falhou', _external=True)
            },
            "auto_return": "approved",
            "notification_url": url_for('webhook', _external=True)
        }

        preference_response = sdk.preference().create(preference_data)
        preference = preference_response.get("response", {})

        if 'init_point' in preference:
            return redirect(preference['init_point'])
        else:
            flash("❌ Erro ao gerar link de pagamento.")
            return redirect(url_for('pagamento'))

    return render_template('pagamento.html')

@app.route('/liberando-acesso')
@login_required
def liberando_acesso():
    return render_template('liberando_acesso.html')

@app.route('/falhou')
@login_required
def falhou():
    flash('❌ Pagamento não concluído. Tente novamente.')
    return redirect(url_for('pagamento'))

@app.route('/calculadora')
@login_required
def calculadora():
    if not current_user.premium:
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
            usuario.senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.session.commit()
            flash('✅ Senha redefinida com sucesso.')
            return redirect(url_for('login'))
    return render_template('redefinir_senha.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/webhook', methods=['POST'])
def webhook():
    print("📩 Webhook recebido")
    print(request.json)

    try:
        data = request.json
        if data and data.get("type") == "payment":
            payment_id = data["data"]["id"]
            print(f"🔍 Verificando pagamento com ID: {payment_id}")

            payment = sdk.payment().get(payment_id)["response"]
            print("💰 Dados do pagamento:", payment)

            if payment.get("status") == "approved":
                email = payment["payer"]["email"]
                usuario = Usuario.query.filter_by(email=email).first()

                if usuario:
                    usuario.premium = True
                    db.session.commit()
                    print(f"✅ Pagamento confirmado para {email}")
                else:
                    print(f"❗ Usuário com e-mail {email} não encontrado.")
            else:
                print(f"⚠️ Pagamento com status: {payment.get('status')}")
        else:
            print("❌ Webhook sem tipo 'payment'")
    except Exception as erro:
        print("❌ Erro no webhook:", erro)

    return '', 200

# 👉 NOVA ROTA pra atualizar o banco no Render
@app.route('/atualizar-banco')
def atualizar_banco():
    try:
        upgrade()
        return '✅ Banco atualizado com sucesso!'
    except Exception as e:
        return f'❌ Erro ao atualizar banco: {e}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
