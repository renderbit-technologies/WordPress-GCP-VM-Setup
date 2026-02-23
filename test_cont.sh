#!/bin/bash
CONT=""
if [[ ! "$CONT" =~ ^[Yy]$ ]]; then
  echo "Aborted"
else
  echo "Continued"
fi
