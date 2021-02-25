"""
Small script to interact with GitHub API using Python.
"""
import os
import argparse
import logging
import requests
from base64 import b64encode
from nacl import encoding, public


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


class GitHub:
    def __init__(self, *, api_key, api_url='https://api.github.com'):
        self.authz_header = {'Authorization': f'Bearer {api_key}'}
        self.api_url = api_url

    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        LOGGER.debug("Cipher a secret using NaCL library...")
        public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return b64encode(encrypted).decode("utf-8")

    def get_organization_public_key(self, organization: str):
        LOGGER.debug("Retrieve public key for organization: %s", organization)
        response = requests.get(
            f'{self.api_url}/orgs/{organization}/actions/secrets/public-key', 
            headers=self.authz_header)
        
        if response.status_code != 200:
            raise Exception(f"Unable to retrieve public key for organization: {organization}.\nResponse: {response.text}")
        return response.json()

    def set_organisation_secret(self, organization: str, secret_name: str, secret_value: str, visibility = 'all'):
        public_key = self.get_organization_public_key(organization)
        encrypted_secret = self.encrypt_secret(public_key["key"], secret_value)

        LOGGER.info("Create or update secret '%s' in organization '%s'", secret_name, organization)
        response = requests.put(
            f'{self.api_url}/orgs/{organization}/actions/secrets/{secret_name}',
            headers=self.authz_header,
            json={"encrypted_value": encrypted_secret, "key_id": public_key["key_id"], "visibility": visibility})

        if response.status_code == 201:
            LOGGER.info('Secret %s created!', secret_name)
        elif response.status_code == 204:
            LOGGER.info('Secret %s updated!', secret_name)
        else:
            error_message = response.text
            raise Exception(f"Error occured creating/updating secret {secret_name}.\n {error_message}")


def parse_args():
    auth_parser = argparse.ArgumentParser(add_help=False)
    auth_parser.add_argument('--key', required=True, help='api key (personal or org access token) used to authenticate in github API')

    parser = argparse.ArgumentParser('github')
    subparsers = parser.add_subparsers(dest='command')

    set_secret_parser = subparsers.add_parser('set-secret', help='create or update a secret from a GitHub organization', parents=[auth_parser])
    set_secret_parser.add_argument('-o', '--org', type=str, required=True, help='name of the organization')
    set_secret_parser.add_argument('-n', '--name', type=str, required=True, help='name of the secret to store')
    value_or_path_group = set_secret_parser.add_mutually_exclusive_group(required=True)
    value_or_path_group.add_argument('-v', '--value', type=str, help='secret value that will be ciphered')
    value_or_path_group.add_argument('-p', '--path', type=str, help='path to a file containing a (multiline) secret value')

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        exit(0)
    return args


def main():
    try:
        args = parse_args()
        
        if args.command == 'set-secret':
            if args.value is None:
                with open(os.path.expanduser(args.path)) as value_file:
                    value = value_file.read()
            else:
                value = args.value
            
            github = GitHub(api_key=args.key)
            github.set_organisation_secret(args.org, args.name, value)
        
    except Exception as error:
        LOGGER.error(str(error))


if __name__ == '__main__':
    main()
