from flask import render_template, abort
from flask_login import login_required, current_user
from . import main
from ..auth.forms import User
from forms import EditProfileForm


@main.route('/')
def index():
    return render_template('index.html')

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username).first()
    if user is None:
        abort(404)
    render_template('user.html', user=user)

