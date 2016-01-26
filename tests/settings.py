INSTALLED_APPS = (
    'fodtlmon_middleware',
)

MIDDLEWARE_CLASSES = (
    'fodtlmon_middleware.middleware.FodtlmonMiddleware',
)


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    },
}

SECRET_KEY = 'notsecure'

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTOCOL', 'https')

ROOT_URLCONF = 'urls'