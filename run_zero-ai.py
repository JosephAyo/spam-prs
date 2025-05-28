import pandas as pd
import papermill as pm  # type: ignore

csv_data = pd.read_csv("repositories_ranked_cleaned.csv")

# Filter to include only 'keycloak/keycloak'
csv_data = csv_data[csv_data["name"] == "keycloak/keycloak"]

notebook_execution_details = []

for index, row in csv_data.iterrows():
    print(f'row["name"]:{row["name"]}')
    notebook_execution_details.append(
        {
            "notebook": "MiningPRs-zero-ai.ipynb",
            "output": f"MiningPRs-zero-ai-{index}-output.ipynb",
            "parameters": {
                "repository_name": row["name"],
                "repository_created_at": row["createdAt"],
                "ignore_indexed_start_date": False,
            },
        }
    )

for notebook_detail in notebook_execution_details:
    notebook = notebook_detail["notebook"]
    notebook_output = notebook_detail["output"]

    print(f"Executing {notebook} and saving as {notebook_output}")
    pm.execute_notebook(
        input_path=notebook,
        output_path=notebook_output,
        parameters=notebook_detail.get("parameters", {}),
    )
    print(f"Executed {notebook} and saved as {notebook_output}")
