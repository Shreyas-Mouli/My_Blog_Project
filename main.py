from flask import Flask, render_template, redirect, url_for, flash, request, abort, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentsForm
from flask_gravatar import Gravatar
from functools import wraps
import os




app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    )



class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    user_blog_posts = db.relationship('BlogPost', backref='the_user')
    the_comments = db.relationship('Comments', backref='the_user_comment')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    blog_comments = db.relationship('Comments', backref='blog_comment')


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_comments = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.ForeignKey('users.id'), nullable=False)
    blog_id = db.Column(db.ForeignKey('blog_posts.id'), nullable=False)




# db.create_all()


def admin_only(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not current_user.is_authenticated or int(current_user.get_id()) != 1:
            return abort(403)
        return f(*args, **kwargs)
    return inner


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user = Users.query.get(1)
    return render_template("index.html", all_posts=posts, admin=user)


@app.route('/register', methods=['GET','POST'])
def register():
    r_form = RegisterForm()
    if request.method == 'POST':
        check = Users.query.filter_by(email=r_form.email.data).first()
        if not check:
            the_password = generate_password_hash(password=r_form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = Users(email=r_form.email.data, password=the_password, name=r_form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("You've already signed up using this email. Please login")
            return redirect(url_for('login'))
    else:
        return render_template("register.html", form=r_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    l_form = LoginForm()
    if request.method == 'POST':
        verify = Users.query.filter_by(email=l_form.email.data).first()
        if verify:
            if check_password_hash(verify.password, l_form.password.data):
                login_user(verify)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password is incorrect')
                return redirect(url_for('login'))
        else:
            flash('Email is not registered')
            return redirect(url_for('login'))
    else:
        return render_template("login.html", form=l_form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comments.query.filter_by(blog_id=post_id).all()
    c_form = CommentsForm()
    if request.method == 'POST':
        if current_user.is_authenticated:
            new_comment = Comments(
                user_comments=c_form.comments.data,
                blog_comment=requested_post,
                the_user_comment=current_user
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('You need to login to register a comment')
            return redirect(url_for('login'))
    else:
        all_blog_comments = {}
        for c in all_comments:
            commenting_user = Users.query.get(c.user_id)
            all_blog_comments[c.user_comments] = commenting_user
        print(all_blog_comments)

        return render_template("post.html", post=requested_post, form=c_form, all_comments=all_blog_comments)


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET','POST'])
@admin_only
@login_required
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            the_user=current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    else:
        return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
