import papermill as pm  # type: ignore

notebooks = [
    "MiningPRs.ipynb",
    "MiningUserOrgsJoinInfo.ipynb",
    "MiningUserContributions.ipynb"
]

for notebook in notebooks:
    pm.execute_notebook(
        notebook,
        f"{notebook}-output.ipynb",
    )
    print(f"Executed {notebook} and saved as output_{notebook}")
