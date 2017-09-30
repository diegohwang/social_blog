# -*- coding:utf-8 -*-
from functools import wraps
from flask import abort
from flask_login import current_user
from models import Permission
'''
让视图函数只对具有特定权限的用户开发
使用自定义的修饰器
'''

#检查常规权限
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return  decorated_function
    return decorator

#检查管理员权限
def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)