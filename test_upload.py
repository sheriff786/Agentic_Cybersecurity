#!/usr/bin/env python3
"""Test script for uploading files to the /scan-file endpoint."""

import requests
import os

def test_file_upload(file_path, description):
    """Test uploading a file to the /scan-file endpoint."""
    url = "http://127.0.0.1:8000/scan-file"
    
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist")
        return
    
    print(f"\nTesting {description}: {file_path}")
    
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        try:
            response = requests.post(url, files=files)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"Decision: {result.get('decision')}")
                print(f"Risk Score: {result.get('risk_score')}")
                print(f"Reason: {result.get('reason')}")
                if result.get('attack_types'):
                    print(f"Attack Types: {result.get('attack_types')}")
            else:
                print(f"Error: {response.text}")
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    # Test files
    test_dir = "test_files"
    
    test_file_upload(os.path.join(test_dir, "sample.txt"), "Plain Text File")
    test_file_upload(os.path.join(test_dir, "sample.json"), "JSON File")
    test_file_upload(os.path.join(test_dir, "sample.py"), "Python Source Code")
    test_file_upload(os.path.join(test_dir, "sample.html"), "HTML File")
    test_file_upload(os.path.join(test_dir, "sample.md"), "Markdown File")
    
    print("\nAll tests completed!")