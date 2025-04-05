import papermill as pm  # type: ignore

notebook_execution_details = [
    {
        "notebook": "MiningPRs-zero-ai.ipynb",
        "output": "MiningPRs-zero-ai-output.ipynb",
        "parameters": {},
    },
]


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
