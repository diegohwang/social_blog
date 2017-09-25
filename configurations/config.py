import ConfigParser
import os
import sys
sys.path.append('.')
basedir = os.path.abspath(os.path.dirname(__file__))

conf = ConfigParser.ConfigParser()
conf.read('configurations/etc.conf')


class Config:
    '''
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    FLASKY_MAIL_SENDER = 'Flasky Admin <diegohwang@163.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    '''


    SECRET_KEY = conf.get('app', 'SECRET_KEY')
    SQLALCHEMY_COMMIT_ON_TEARDOWN = conf.getboolean('app', 'SQLALCHEMY_COMMIT_ON_TEARDOWN')
    SQLALCHEMY_TRACK_MODIFICATIONS = conf.getboolean('app', 'SQLALCHEMY_TRACK_MODIFICATIONS')
    FLASKY_MAIL_SUBJECT_PREFIX = conf.get('mail', 'FLASKY_MAIL_SUBJECT_PREFIX')
    FLASKY_MAIL_SENDER = conf.get('mail', 'FLASKY_MAIL_SENDER')
    FLASKY_ADMIN = conf.get('mail', 'FLASKY_ADMIN')

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = conf.get('mail', 'MAIL_SERVER')
    MAIL_PORT = conf.getint('mail', 'MAIL_PORT')
    MAIL_USE_SSL = conf.getboolean('mail', 'MAIL_USE_SSL')
    MAIL_USERNAME = conf.get('mail', 'MAIL_USERNAME')
    MAIL_PASSWORD = conf.get('mail', 'MAIL_PASSWORD')
    SQLALCHEMY_DATABASE_URI = conf.get('app', 'SQLALCHEMY_DATABASE_URI')

config = {
    'development': DevelopmentConfig,
    'default': DevelopmentConfig
}