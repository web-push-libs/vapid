#!/bin/sh
# Package the current branch up to pypi
# remember to update the README.rst file
#pandoc --from=markdown --to=rst --output README.rst README.md
#pandoc --from=markdown --to=rst --output CHANGELOG.rst CHANGELOG.md
venv/bin/python setup.py sdist
venv/bin/twine upload dist/* --verbose
