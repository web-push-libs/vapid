import io
import os

from setuptools import setup, find_packages

__version__ = "1.9.1"


def read_from(file):
    reply = []
    with io.open(os.path.join(here, file), encoding='utf8') as f:
        for l in f:
            l = l.strip()
            if not l:
                break
            if l[:2] == '-r':
                reply += read_from(l.split(' ')[1])
                continue
            if l[0] != '#' or l[:2] != '//':
                reply.append(l)
    return reply


here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst'), encoding='utf8') as f:
    README = f.read()
#with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
#    CHANGES = f.read()

setup(name="py-vapid",
      version=__version__,
      description='Simple VAPID header generation library',
      long_description=README,
      long_description_content_type="text/x-rst",
      classifiers=["Topic :: Internet :: WWW/HTTP",
                   "Programming Language :: Python",
                   "Programming Language :: Python :: 3",
                   ],
      keywords='vapid push webpush',
      author="JR Conlin",
      author_email="src+vapid@jrconlin.com",
      url='https://github.com/mozilla-services/vapid',
      license="MPL2",
      include_package_data=True,
      zip_safe=False,
      packages=find_packages(),
      package_data={'': ['README.rst',
                         'requirements.txt', 'test-requirements.txt']},
      install_requires=read_from('requirements.txt'),
      tests_require=read_from('test-requirements.txt'),
      entry_points="""
      [console_scripts]
      vapid = py_vapid.main:main
      """,
      )
