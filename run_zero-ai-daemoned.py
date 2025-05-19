import daemon
import pandas as pd
import papermill as pm  # type: ignore
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import argparse


def run_notebook_batch(start_idx, end_idx, csv_data):
    notebook_execution_details = []

    # Iterating through the selected range of rows
    for index in range(start_idx, end_idx):
        row = csv_data.iloc[index]
        notebook_execution_details.append(
            {
                "notebook": "MiningPRs-zero-ai.ipynb",
                "output": f"MiningPRs-zero-ai-{row['name'].replace('/', '__')}-output.ipynb",
                "parameters": {
                    "repository_name": row["name"],
                    "repository_created_at": row["createdAt"],
                },
            }
        )

    for notebook_detail in notebook_execution_details:
        notebook = notebook_detail.get("notebook")
        notebook_output = notebook_detail.get("output")
        repo_name = notebook_detail.get("parameters").get("repository_name")
        start_time = time.time()
        print(
            f"Executing {repo_name} notebook saving as {notebook_output}",
            file=sys.stdout,
        )
        pm.execute_notebook(
            input_path=notebook,
            output_path=notebook_output,
            parameters=notebook_detail.get("parameters", {}),
        )
        end_time = time.time()
        print(f"Executed {repo_name} and saved as {notebook_output}", file=sys.stdout)
        print(
            f"Execution time for {repo_name}: {end_time - start_time:.2f} seconds",
            file=sys.stdout,
        )


def main():
    # Parsing command-line arguments
    parser = argparse.ArgumentParser(description="Run notebooks concurrently.")
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of threads for concurrent execution.",
    )
    args = parser.parse_args()
    num_threads = args.threads

    log_path = "/tmp/notebook_daemon.log"
    err_path = "/tmp/notebook_daemon_error.log"
    # Read the file "completed_repos.txt" and filter out the repo names
    completed_repos = set()
    if os.path.exists("completed_repos.txt"):
        with open("completed_repos.txt", "r") as f:
            completed_repos = set(line.strip() for line in f if line.strip())

    # Limit to the first 385 repositories before filtering out the completed ones
    csv_data = pd.read_csv("repositories_ranked_cleaned.csv")
    csv_data = csv_data.head(385)
    csv_data = csv_data[~csv_data["name"].isin(completed_repos)]
    total_rows = len(csv_data)
    chunk_size = total_rows // num_threads
    futures = []

    # Create separate ranges for concurrent processing
    with daemon.DaemonContext(
        stdout=open(log_path, "a+"),
        stderr=open(err_path, "a+"),
        working_directory=os.getcwd(),
        umask=0o002,
    ):
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for i in range(num_threads):
                start_idx = i * chunk_size
                # Ensure the last chunk handles any remaining rows
                end_idx = (i + 1) * chunk_size if i != num_threads - 1 else total_rows
                futures.append(
                    executor.submit(run_notebook_batch, start_idx, end_idx, csv_data)
                )

            # Wait for all futures to complete
            for future in futures:
                future.result()

        with open(log_path, "a+") as log_file:
            log_file.write("All notebooks have been executed successfully.\n")


if __name__ == "__main__":
    main()
