import csv
import json
import requests
import itertools
import random
import os

# Read tokens from a text file
tokens_file = "./env/zero-ai-tokens.txt"
with open(tokens_file, "r") as file:
    tokens = file.read().splitlines()

# Choose a random start index
start_index = random.randint(0, len(tokens) - 1)

# Rotate the tokens list starting at a random position
rotated_tokens = tokens[start_index:] + tokens[:start_index]

# Create an infinite cycle iterator from the rotated list
token_iterator = itertools.cycle(rotated_tokens)

# Define API endpoint
url = "https://api.zerogpt.com/api/detect/detectText"

# CSV input and output file paths
input_csv_path = "../datasets/molssi__qcfractal/molssi__qcfractal-progress.csv"
output_csv_path = "../datasets/molssi__qcfractal/molssi__qcfractal-detection.csv"

# Ensure output directory exists
os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)

# Read input and prepare to write output
with open(input_csv_path, mode="r", encoding="utf-8") as input_file, open(
    output_csv_path, mode="w", encoding="utf-8", newline=""
) as output_file:

    reader = csv.DictReader(input_file)
    rows = itertools.islice(reader, None)  # Adjust or remove the limit as needed
    writer = csv.DictWriter(
        output_file,
        fieldnames=[
            "id",
            "repository_name_with_owner",
            "url",
            "created_at",
            "updated_at",
            "bodyText",
            "zerogpt_response",
        ],
    )

    writer.writeheader()

    for row in rows:
        body_text = row.get("bodyText", "")
        zerogpt_response = ""

        if body_text:
            current_token = next(token_iterator)
            payload = json.dumps({"input_text": body_text})
            headers = {
                "ApiKey": current_token,
                "Content-Type": "application/json",
            }

            try:
                response = requests.post(url, headers=headers, data=payload)
                response_data = response.json()
                zerogpt_response = json.dumps(response_data)
            except Exception as e:
                zerogpt_response = f"Error: {e}"
                print(f"Error processing row id {row.get('id', '')}: {e}")
            else:
                print(f"Successfully processed row id {row.get('id', '')}")

        output_row = {
            "id": row.get("id", ""),
            "repository_name_with_owner": row.get("repository_name_with_owner", ""),
            "bodyText": body_text,
            "url": row.get("url", ""),
            "created_at": row.get("created_at", ""),
            "updated_at": row.get("updated_at", ""),
            "zerogpt_response": zerogpt_response,
        }
        writer.writerow(output_row)
