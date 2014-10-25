"""
Flask-Tokens
-------------

Flask-Tokens handles token-based authentication for Flask applications.
"""
from setuptools import setup


setup(
    name='Flask-Tokens',
    version='0.1',
    url='http://github.com/uppfinnarn/Flask-Tokens',
    license='MIT',
    author='Johannes Ekberg',
    author_email='uppfinnarn@example.com',
    description='Token authentication for your Flask applications',
    long_description=__doc__,
    py_modules=['flask_tokens'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'pyjwt'
    ],
    tests_require=[
        'Flask-Testing'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
