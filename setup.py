import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()
CHANGELOG = open(os.path.join(here, 'CHANGELOG.rst')).read()

requires = [
    'boto==2.38.0',
    'moto==0.4.10',
    'Zambi==1.0',
    'nvlib==1.0',
    'ipaddr==2.1.11',
    ]

setup(name='c3',
      package=['c3'],
      version='0.2',
      description='CloudCloudCloud - Provisions AWS services from easy to read ini configs',
      long_description=README + '\n\n' + CHANGELOG,
      classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Intended Audience :: System Administrators ",
        ],
      scripts=[
        'scripts/C3EC2Provision.py',
        'scripts/c3s3provision.py',
        'scripts/c3nv2route53.py',
      ],
      author='Jesse Escobedo',
      author_email='jesse@moda.bz',
      url='https://github.com/jesco39/c3',
      license='Apache',
      keywords='C3 AWS automation cgm cloud devops',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite='nose.collector',
      )
