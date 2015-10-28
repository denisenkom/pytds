How to release new version to pypi
==================================

Make sure you don't have any local changes and that you are on
the right branch by running:

 git status

Verify that Travis CI tests are passing for current branch.

Update version in pytds/__init__.py and commit

Tag current commit by running:

 git tag -a <version>

Check build:

 python setup.py sdist

Push to github:

 git push && git push --tags

Upload to pypi:

 python setup.py sdist upload
