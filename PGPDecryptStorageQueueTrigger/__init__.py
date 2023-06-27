import json
import logging
import gnupg
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func
from azure.storage.blob import BlobServiceClient
import os
from smart_open import open
gpg = gnupg.GPG(gnupghome="/tmp")


def getSecrets(vaulturl):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vaulturl,credential=credential)
    secret = client.get_secret("private-key1")
    private_key = secret.value
    secret = client.get_secret("passphrase1")
    passphrase = secret.value
    return private_key,passphrase

def pgpDecrypt(private_key,passphrase,encrypt_file,container,source_transport_params,destination_transport_params):
    gpg.import_keys(key_data=private_key,passphrase=passphrase)
    logging.info(gpg.list_keys())
    logging.info(gpg.gnupghome)
    if encrypt_file[-4:] == ".gpg":
        decrypt_file = encrypt_file[:-4]
        print(decrypt_file)
        with open('azure://{}/{}'.format(container,encrypt_file), 'rb', transport_params=source_transport_params) as ef:
            status = gpg.decrypt_file(ef,passphrase=passphrase)
        with open('azure://{}/{}'.format(container,decrypt_file), 'wb', transport_params=destination_transport_params) as df:
            data = status.data
            df.write(data)
        #print(type(status.data))
        logging.info(f"{decrypt_file}")
        logging.info(f"{status.ok}")
        logging.info(f"{status.stderr}")

def main(msg: func.QueueMessage) -> None:
    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))
    logging.info(f"{msg.get_json()}")
    blob_url = msg.get_json()['data']['url']
    url_parts = blob_url.split("/")
    # Extracting the container name and filename with path
    container_name = url_parts[3]
    blob_name_with_path = "/".join(url_parts[4:])

    print("Container name:", container_name)
    print("Filename with path:", blob_name_with_path)
    source_connection_string = os.environ['AzureWebJobsStorage']
    destination_connection_string = os.environ['DestinationStorageConnectionString']
    source_transport_params = {
        'client': BlobServiceClient.from_connection_string(source_connection_string),
    }
    destination_transport_params = {
        'client': BlobServiceClient.from_connection_string(destination_connection_string),
    }
    logging.info(f"GPG Home {gpg.gnupghome}")
    logging.info(f"{blob_url},{container_name},{blob_name_with_path}\n")
    private_key, passphrase = getSecrets("https://pgpkeys1.vault.azure.net/")
    logging.info(f"current working directory: {os.getcwd()}")
    pgpDecrypt(private_key,passphrase,blob_name_with_path,container_name,source_transport_params,destination_transport_params)