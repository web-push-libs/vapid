#!/bin/sh
# Package the current branch up to pypi
# remember to update the README.rst file
pandoc --from=markdown --to=rst --output README.rst README.md
bin/python setup.py sdist
bin/twine upload dist/*
