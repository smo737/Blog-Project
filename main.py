from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
#from sqlalchemy import Table, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    blogs = relationship("BlogPost",  back_populates="author")
    comments = relationship("Comment", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="blogs")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="blog")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body = db.Column(db.Text, nullable=False)
    author = relationship("User", back_populates="comments")
    blog = relationship("BlogPost", back_populates="comments")

#db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Admin check")
        if not current_user.is_authenticated or current_user.id != 1:
            return "Forbidden. You do not have administrator access.", 403
        return func(*args, **kwargs)
    return wrapper



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    reg_form = RegisterForm()
    if request.method == "POST":
        if reg_form.validate_on_submit():
            check_user = db.session.query(User).filter_by(email=reg_form.email.data).first()
            if check_user:
                flash("Email already exists. Please login.")
                return redirect("/login")
            new_user = User()
            new_user.name = reg_form.name.data
            new_user.email = reg_form.email.data
            new_user.password = generate_password_hash(reg_form.password.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect('/')
        else:
            return redirect('/register', logged_in=current_user.is_authenticated)
    else:
        return render_template("register.html", form=reg_form)

@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if request.method == "POST":
        if login_form.validate_on_submit():
            req_user = db.session.query(User).filter_by(email=login_form.email.data).first()
            if not req_user:
                flash("User not found")
                return redirect("/login")
            if check_password_hash(req_user.password, login_form.password.data):
                login_user(req_user)
                return redirect("/")
            else:
                flash("Incorrect password")
                return redirect("/login")


    return render_template("login.html", logged_in=current_user.is_authenticated, form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit() and comment_form.body != "":
        new_comment = Comment(user_id = current_user.id,
                              blog_id = requested_post.id,
                              body = comment_form.body.data)
        db.session.add(new_comment)
        db.session.commit()
        return redirect (f"/clear-post/{post_id}")

    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=comment_form)

@app.route("/clear-post/<int:post_id>")
def clear_post(post_id):
    print("redirecting")
    return redirect(f"/post/{post_id}")

@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)

@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            user_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)

@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
