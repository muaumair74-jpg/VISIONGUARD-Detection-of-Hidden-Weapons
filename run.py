"""
VisionGuard React — Entry Point
Run: python run.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
import uvicorn

# Ensure DATA_BACKEND / DATABASE_URL / AUTH_TOKEN_PEPPER from .env are loaded before app import.
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from backend.main import app

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡  VisionGuard React — AI Threat Detection")
    print("=" * 55)
    print("  → API server:   http://localhost:8000")
    print("  → React dev:    http://localhost:3000  (npm run dev)")
    print("  → Production:   http://localhost:8000  (after npm run build)")
    print("=" * 55)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
