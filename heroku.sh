#!/bin/bash
gunicorn manage:app --daemon
python worker.py