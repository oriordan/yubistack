#!/bin/bash

if [ -z "$2" ]; then
  echo "py$1" | tr -d '.'
else
  echo "$2"
fi