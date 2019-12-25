import sys
from botocore.exceptions import ClientError

from secureaws import common

def create_rsa_key_pair(file_name="", key_size=4096):
    """
    This will generate a new custom RSA key pair
    """

    try:
        sys.stdout.write("Generating Key Pair... ")
        sys.stdout.flush()
        from Cryptodome.PublicKey import RSA

        new_key = RSA.generate(key_size)
        public_key = new_key.publickey().exportKey('OpenSSH')
        private_key = new_key.exportKey()
        
        pvt_file = "private-key-{}.pem".format(common.random_string(5)) if file_name == "" or file_name is None else "{}.pem".format(file_name)
        pub_file = "public-key-{}.pub".format(common.random_string(5)) if file_name == "" or file_name is None else "{}.pub".format(file_name)
        
        file_out = open(pvt_file, "wb")
        file_out.write(private_key)

        file_out = open(pub_file, "wb")
        file_out.write(public_key)

        print("Ok")
        print("Private Key: {}".format(pvt_file))
        print("Public Key: {}".format(pub_file))
        return True
    except ClientError as e:
        print("Error: " + e.response['Error']['Code'] + " - " + e.response['Error']['Message'])
        return False
    except Exception as ex:
        print("Error: {}".format(ex))
        return False