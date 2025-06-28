import os
import sys
import google.generativeai as genai
from dotenv import load_dotenv

print("="*80)
print("🚀 Starting Standalone Google AI Connection Test...")
print("="*80)

print("1. Loading .env file...")
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
model_name = os.getenv("GEMINI_MODEL_NAME")

if not api_key:
    print("\n❌ TEST FAILED: The GOOGLE_API_KEY was not found in your .env file.")
    sys.exit(1)

masked_key = f"{api_key[:5]}...{api_key[-4:]}"
print(f"2. Loaded variables -> Key: {masked_key} | Model: {model_name}")

print("\n3. Attempting to configure the Google AI client and create the model...")
try:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name=model_name)

    print("\n" + "="*30 + " ✅ SUCCESS! " + "="*30)
    print("Your API key and model name are CORRECT and the connection to Google AI works.")
    print("="*80)

except Exception as e:
    print("\n" + "="*30 + " ❌ TEST FAILED! " + "="*30)
    print("This is the TRUE reason your application is failing.")
    print("\n--- EXACT ERROR MESSAGE ---")
    print(e)
    print("---------------------------\n")
