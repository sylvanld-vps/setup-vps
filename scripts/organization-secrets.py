"""
Small script to set secret from GitHub action.
"""
import requests
from base64 import b64encode
from nacl import encoding, public


class GitHub:
    def __init__(self, *, api_key, api_url='https://api.github.com'):
        self.authz_header = {'Authorization': f'Bearer {api_key}'}
        self.api_url = api_url

    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return b64encode(encrypted).decode("utf-8")

    def get_organization_public_key(self, organization: str):
        response = requests.get(
            f'{self.api_url}/orgs/{organization}/actions/secrets/public-key', 
            headers=self.authz_header)
        if response.status_code != 200:
            raise Exception(f"Unable to retrieve public key for organization: {organization}")
        return response.json()

    def set_organisation_secret(self, organization: str, secret_name: str, secret_value: str, visibility = 'all'):
        # retrieve public key to encrypt secret
        public_key = self.get_organization_public_key(organization)

        # encrypt secret before storing it in GitHub
        encrypted_secret = self.encrypt_secret(public_key["key"], secret_value)

        # create or update secret using GitHub API
        response = requests.put(
            f'{self.api_url}/orgs/{organization}/actions/secrets/{secret_name}',
            headers=self.authz_header,
            json={"encrypted_value": encrypted_secret, "key_id": public_key["key_id"], "visibility": visibility})

        if response.status_code == 201:
            print(f'Secret {secret_name} created!')
        elif response.status_code == 204:
            print(f'Secret {secret_name} updated!')
        else:
            error_message = response.text
            raise Exception(f"Error occured creating/updating secret {secret_name}.\n {error_message}")
    
if __name__ == '__main__':
  github = GitHub(api_key="4ac04f4e2157527119d8742254a14be6a261fd22")
  # usage: github.set_organisation_secret("sylvanld-vps", "ssh_private_key", ssh_private_key)
