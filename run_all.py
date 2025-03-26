import papermill as pm  # type: ignore

notebook_execution_details = [
    {
        "notebook": "MiningPRs.ipynb",
        "output": "MiningPRs-output.ipynb",
        "parameters": {},
    },
    {
        "notebook": "MiningUserOrgsJoinInfo.ipynb",
        "output": "MiningUserOrgsJoinInfo-output.ipynb",
        "parameters": {
            "is_mining_spam": True,
        },
    },
    {
        "notebook": "MiningUserContributions.ipynb",
        "output": "MiningUserContributions-output.ipynb",
        "parameters": {},
    },
    {
        "notebook": "MiningPRTimeline.ipynb",
        "output": "MiningPRTimeline-output.ipynb",
        "parameters": {
            "is_mining_spam": True,
        },
    },
    {
        "notebook": "MiningPRFiles.ipynb",
        "output": "MiningPRFiles-output.ipynb",
        "parameters": {},
    },
    {
        "notebook": "MiningNonSpamPRs.ipynb",
        "output": "MiningNonSpamPRs-output.ipynb",
        "parameters": {},
    },
    {
        "notebook": "MiningUserOrgsJoinInfo.ipynb",
        "output": "MiningUserOrgsJoinInfo-output.ipynb",
        "parameters": {
            "is_mining_spam": False,
        },
    },
    {
        "notebook": "MiningPRTimeline.ipynb",
        "output": "MiningPRTimeline-output.ipynb",
        "parameters": {
            "is_mining_spam": False,
        },
    },
    {
        "notebook": "MiningPRFiles.ipynb",
        "output": "MiningPRFiles-output.ipynb",
        "parameters": {
            "is_mining_spam": False,
        },
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
        # parameters=dict(alpha=0.6, ratio=0.1),
    )
    print(f"Executed {notebook} and saved as {notebook_output}")
