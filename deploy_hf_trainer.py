import os
import sys
from huggingface_hub import HfApi
from dotenv import load_dotenv

def main():
    load_dotenv()
    token = os.getenv("HF_TOKEN")
    if not token:
        print("ERROR: HF_TOKEN environment variable is missing in .env")
        sys.exit(1)
        
    api = HfApi(token=token)
    user = api.whoami()["name"]
    space_id = f"{user}/CVE-RL-Trainer"
    
    print(f"Creating Hugging Face Space: {space_id}...")
    try:
        api.create_repo(
            repo_id=space_id,
            repo_type="space",
            space_sdk="docker",
            private=True,
            exist_ok=True
        )
        print("Space created successfully.")
    except Exception as e:
        print(f"Error creating space: {e}")
        sys.exit(1)
        
    # Create a Dockerfile for JupyterLab
    dockerfile_content = """
FROM huggingface/spaces-jupyter:latest
# Install required dependencies for Unsloth & RL
RUN pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
RUN pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
RUN pip install --no-deps trl peft accelerate bitsandbytes
"""
    with open("Dockerfile_jupyter", "w") as f:
        f.write(dockerfile_content.strip())
        
    print("Uploading training notebook and environment files...")
    
    # Upload Dockerfile
    api.upload_file(
        path_or_fileobj="Dockerfile_jupyter",
        path_in_repo="Dockerfile",
        repo_id=space_id,
        repo_type="space"
    )
    
    # Upload notebook
    api.upload_file(
        path_or_fileobj="train_rl.ipynb",
        path_in_repo="train_rl.ipynb",
        repo_id=space_id,
        repo_type="space"
    )
    
    # Upload environment folder
    api.upload_folder(
        folder_path="environment",
        path_in_repo="environment",
        repo_id=space_id,
        repo_type="space"
    )
    
    print("Files uploaded!")
    print(f"Setting Space Hardware to T4 GPU (This will start using your Hugging Face credits!)...")
    
    try:
        api.request_space_hardware(repo_id=space_id, hardware="t4-small")
        print("Hardware successfully requested!")
    except Exception as e:
        print(f"Warning on hardware request: {e}")
        print("You may need to manually select the GPU in the Space settings.")
        
    print("\n" + "="*50)
    print("SUCCESS! Your Training Space is ready.")
    print("="*50)
    print(f"Link: https://huggingface.co/spaces/{space_id}")
    print("\nNext Steps:")
    print("1. Go to the link above.")
    print("2. Open 'train_rl.ipynb' in the Jupyter interface.")
    print("3. Run all cells to train the model using your credits.")
    print("4. IMPORTANT: When finished, pause the Space in Settings to stop using credits!")

if __name__ == "__main__":
    main()
