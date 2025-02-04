import requests
from bs4 import BeautifulSoup
import json


def get_repo_org_members(repository_name_with_owner: str):
    """
    Fetches the list of organization members for a given GitHub repository.
    Args:
      repository_name_with_owner (str): The repository name with owner in the format 'owner/repo'.
    Returns:
      list: A list of dictionaries containing 'username' and 'user_id' of each member.
          Returns None if an error occurs during the request or parsing.
    Raises:
      requests.exceptions.RequestException: If there is an issue with the HTTP request.
      Exception: For any other exceptions that may occur.
    """

    try:
        members_url = (
            f"https://github.com/orgs/{repository_name_with_owner.split('/')[0]}/people"
        )
        response = requests.get(members_url)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")

        # Find all user elements
        users = soup.find_all("li", class_="member-list-item")

        # Extract user details
        user_details = []
        for user in users:
            username = user.find("a", class_="f4 d-block").text.strip()
            user_id = user["data-bulk-actions-id"]
            user_details.append({"username": username, "user_id": user_id})

        return user_details

    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


if __name__ == "__main__":
    repository_name_with_owner = input(
        "Enter the GitHub repository_name_with_owner (e.g., owner/repo): "
    )
    members = get_repo_org_members(repository_name_with_owner)

    if members is not None:
        if members:
            print("Members")
            for member in members:
                print(f"- {member}")
        else:
            print(
                "No members found (or perhaps the repository is private, or you are not authorized to view it, or GitHub page structure changed)."
            )
