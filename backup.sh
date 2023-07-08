#!/bin/bash

cd public
git add .
git commit -m "new post"
git push
cd ../

git add .
git commit -m "backup"
git push

