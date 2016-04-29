import io
import os

from setuptools import setup, find_packages

__version__ = "0.2"

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
    CHANGES = f.read()
with io.open(os.path.join(here, 'requirements.txt'), encoding='utf8') as f:
    REQS = []
    for l in f:
        l = l.strip()
        if not l:
            break
        if l[0] == '#' or l[:2] == '//':
            continue
        REQS.append(l)

setup(name="py-vapid",
      version=__version__,
      description='Simple VAPID header generation library',
      long_description=README + '\n\n' + CHANGES,
      classifiers=["Topic :: Internet :: WWW/HTTP",
                   'Programming Language :: Python',
                   "Programming Language :: Python :: 2",
                   "Programming Language :: Python :: 2.7"
                   ],
      keywords='vapid',
      author="JR Conlin",
      author_email="src+vapid@jrconlin.com",
      url='https://github.com/mozilla-services/vapid',
      license="MPL2",
      test_suite="nose.collector",
      include_package_data=True,
      zip_safe=False,
      tests_require=['nose', 'coverage', 'mock>=1.0.1'],
      packages=find_packages(),
      install_requires=REQS,
      entry_points="""
      [console_scripts]
      vapid = py_vapid.main:main
      [nose.plugins]
      object-tracker = autopush.noseplugin:ObjectTracker
      """,
      )
