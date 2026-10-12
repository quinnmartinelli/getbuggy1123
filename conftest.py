import os
import sys

# Makes core.py/server.py/embedded_form_providers.py/etc. importable from
# tests/ regardless of what directory pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
