#!/bin/bash
set -u
if [[ ! "$CONT" =~ ^[Yy]$ ]]; then
  echo "Aborted"
fi
