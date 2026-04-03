import os
import sys
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Required Pre-Submission Checklist Variables
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3-8b-instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

# Optional - if you use from_docker_image():
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

def run_inference(task_input: str):
    # 1. Stdout logs follow the required structured format START
    print("START")

    try:
        # 2. All LLM calls use the OpenAI client configured via these variables
        client = OpenAI(
            base_url=API_BASE_URL,
            api_key=HF_TOKEN or os.getenv("OPENAI_API_KEY", "dummy-key")
        )

        print(f"STEP: Processing vulnerability scan task using {MODEL_NAME}...")

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a Nexus Security Vulnerability Scanner AI. Analyze the input for security flaws."},
                {"role": "user", "content": task_input}
            ]
        )

        output = response.choices[0].message.content
        print(f"STEP: Finalizing security report...")
        print(output)

    except Exception as e:
        print(f"STEP: Error occurred during inference - {str(e)}")

    finally:
        # 3. Stdout logs follow the required structured format END
        print("END")

if __name__ == "__main__":
    # Ensure it can accept command line inputs when run by the hackathon evaluator
    user_input = sys.argv[1] if len(sys.argv) > 1 else "Hello, perform a default security audit."
    run_inference(user_input)
