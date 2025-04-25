import pandas as pd

import papermill as pm  # type: ignore

csv_data = pd.read_csv("repositories_ranked_cleaned.csv")
notebook_execution_details = []

# Iterate through each row in the CSV file
for index, row in csv_data.iterrows():
    notebook_execution_details.append({
        "notebook": "MiningPRs-zero-ai.ipynb",
        "output": f"MiningPRs-zero-ai-{index}-output.ipynb",
        "parameters": {
            "repository_name": row["name"],
            "repository_created_at": row["createdAt"],
        },
    })


for notebook_detail in notebook_execution_details:
    notebook = notebook_detail.get("notebook")
    notebook_output = f"{notebook_detail.get("output")}"

    print(f"Executing {notebook} and saving as {notebook_output}")
    pm.execute_notebook(
        input_path=notebook,
        output_path=notebook_output,
        parameters=notebook_detail.get("parameters", {}),
    )
    print(f"Executed {notebook} and saved as {notebook_output}")
