import logging
import gnupg
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func
gpg = gnupg.GPG(gnupghome="./dependency/gnupg-2.2.41")
gpg = gnupg.GPG()

def getSecrets(vaulturl):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vaulturl,credential=credential)
    secret = client.get_secret("private-key1")
    private_key = secret.value
    secret = client.get_secret("passphrase1")
    passphrase = secret.value
    return private_key,passphrase


def pgpDecrypt(private_key,passphrase,decryptedBlob,encryptedBlob,):
    gpg.import_keys(key_data=private_key,passphrase=passphrase)
    status = gpg.decrypt(encryptedBlob ,passphrase=passphrase)
    decryptedBlob.set(status.data)
    #print(type(status.data))
    logging.info(f"{status.ok}\n")
    logging.info(f"{status.stderr}\n")


def main(encryptedTriggerBlob: func.InputStream,decryptedBlob: func.Out[bytes]):
    private_key, passphrase = getSecrets("https://pgpkeys1.vault.azure.net/")
    pgpDecrypt(private_key,passphrase,decryptedBlob,encryptedBlob=encryptedTriggerBlob.read())

