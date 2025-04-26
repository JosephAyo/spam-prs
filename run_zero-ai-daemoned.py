import daemon
import pandas as pd
import papermill as pm  # type: ignore
import time
import os
import sys


def run_notebook_batch():
    csv_data = pd.read_csv("repositories_ranked_cleaned.csv")
    notebook_execution_details = []

    for index, row in csv_data.iterrows():
        notebook_execution_details.append(
            {
                "notebook": "MiningPRs-zero-ai.ipynb",
                "output": f"MiningPRs-zero-ai-{row["name"].replace("/", "__")}-output.ipynb",
                "parameters": {
                    "repository_name": row["name"],
                    "repository_created_at": row["createdAt"],
                },
            }
        )

    for notebook_detail in notebook_execution_details:
        notebook = notebook_detail.get("notebook")
        notebook_output = notebook_detail.get("output")
        repo_name = notebook_detail.get('parameters').get('repository_name')
        start_time = time.time()
        print(f"Executing {repo_name} notebook saving as {notebook_output}", file=sys.stdout)
        pm.execute_notebook(
            input_path=notebook,
            output_path=notebook_output,
            parameters=notebook_detail.get("parameters", {}),
        )
        end_time = time.time()
        print(f"Executed {repo_name} and saved as {notebook_output}", file=sys.stdout)
        print(f"Execution time for {repo_name}: {end_time - start_time:.2f} seconds", file=sys.stdout)


def main():
    log_path = "/tmp/notebook_daemon.log"
    err_path = "/tmp/notebook_daemon_error.log"

    with daemon.DaemonContext(
        stdout=open(log_path, "a+"),
        stderr=open(err_path, "a+"),
        working_directory=os.getcwd(),
        umask=0o002,
    ):
        run_notebook_batch()
        with open(log_path, "a+") as log_file:
            log_file.write("All notebooks have been executed successfully.\n")


if __name__ == "__main__":
    main()
