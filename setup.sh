#!/usr/bin/env bash
set -e
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
echo "OK. Active le venv avec : source .venv/bin/activate"
echo "Puis renseigne tes clés dans .env"
