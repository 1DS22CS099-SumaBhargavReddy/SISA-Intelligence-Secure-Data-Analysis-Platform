import sys
import os

# Add the project root and backend folder to the path to enable serverless importing
# This structure ensures all 'from backend.xxx import yyy' and 'from xxx import yyy' will work
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, "backend"))

from backend.main import app
