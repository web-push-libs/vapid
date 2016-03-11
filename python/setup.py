import io
import os

from vapid import __version__
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
    CHANGES = f.read()

extra_options = {
    "packages": find_packages(),
}
setup(name="VAPID library",
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
      author_email="jrconlin+src@jrconlin.com",
      url='http:///',
      license="MPL2",
      test_suite="nose.collector",
      include_package_data=True,
      zip_safe=False,
      tests_require=['nose', 'coverage', 'mock>=1.0.1'],
      entry_points="""
      [console_scripts]
      vapid = vapid.main:main
      [nose.plugins]
      object-tracker = autopush.noseplugin:ObjectTracker
      """,
      **extra_options
      )
