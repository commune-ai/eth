import os
from typing import *
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from eth_account.account import Account
from eth_account.hdaccount import ETHEREUM_DEFAULT_PATH, key_from_seed, seed_from_mnemonic
from eth_account.messages import SignableMessage, encode_defunct
from eth_utils.curried import combomethod,keccak,text_if_str,to_bytes
from eth_keys import keys
import commune as c # import commune

class Key(Account, c.Module):
    key_storage_path = '~/.eth/key'
    def __init__(self, private_key: str = None) -> None:
        if self.key_exists(private_key):
            self.load_key(private_key)
        else:
            self.private_key =  private_key or  self.create_private_key()

    def resolve_message(self, message) :
        message = c.python2str(message)
        if isinstance(message, str):
            message = encode_defunct(text=message)
        elif isinstance(message, SignableMessage):
            message = message
        else:
            raise NotImplemented
        return message
    
    def is_valid_private_key(self, private_key):
        try:
            key = keys.PrivateKey(private_key)
            return True
        except:
            return False
    
    @property
    def private_key_string(self) -> str:
        private_key = self._private_key
        if isinstance(private_key, bytes):
            private_key = private_key.hex()
        if not private_key.startswith('0x'):
            private_key = '0x' + private_key
        return private_key

    @property
    def private_key(self) -> bytes:
        return self._private_key
    
    @private_key.setter
    def private_key(self, private_key:str):
        if isinstance(private_key, str):
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            private_key = bytes.fromhex(private_key)
        self._private_key = private_key
        return private_key
                    
    def sign(self, message: Union[SignableMessage,str, dict]) -> Dict:
        signable_message = self.resolve_message(message)
        signed_msg =  Account.sign_message(signable_message, self.private_key)
        return {
            'message': signed_msg.message_hash.hex(),
            'signature': signed_msg.signature.hex(),
            'vrs': [signed_msg.v, signed_msg.r, signed_msg.s],
            'address': self.address
        }


    @property
    def public_key(self) -> str:
        return self.private_key_to_public_key(self.private_key)
    
    @property
    def address(self):
        return self.public_key_to_address(self.public_key.to_hex())
    
    @classmethod
    def address_to_public_key(cls, address:str) -> str:
        '''
        Convert address to public key
        '''
        if address.startswith('0x'):
            address = address[2:]
        address = bytes.fromhex(address)
        return address.hex()
        
    def public_key_to_address(self, public_key: str) -> str:
        '''
        Convert public key to address
        '''
        if public_key.startswith('0x'):
            public_key = public_key[2:]
        public_key = bytes.fromhex(public_key)
        return keys.PublicKey(public_key).to_checksum_address()
    
    @staticmethod
    def private_key_to_public_key(private_key: str) -> str:
        '''
        Conert private key to public key
        '''
        private_key_object = keys.PrivateKey(private_key)
        return private_key_object.public_key

    
    def verify(self, message:Any, 
               signature:str = None, 
               vrs:Union[tuple, list]=None, 
               address:str=None) -> bool:
        '''
        verify message from the signature or vrs based on the address
        '''
        recovered_address = Account.recover_message(message, vrs=vrs, signature=signature)
        return bool(recovered_address == address)
    

       
    @classmethod
    def from_password(cls, password:str, salt:str='commune', prompt=False):
        
        from web3.auto import w3
        from Crypto.Protocol.KDF import PBKDF2
        # Prompt the user for a password and salt
        if prompt :
            password = input("Enter password: ")
        # Derive a key using PBKDF2
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        # Create an account using the key
        account = cls.from_key(key)
        return account

    @combomethod
    def create(self, extra_entropy=""):
        r"""
        Creates a new private key, and returns it as a
        :class:`~eth_account.local.Key`.

        :param extra_entropy: Add extra randomness to whatever randomness your OS
          can provide
        :type extra_entropy: str or bytes or int
        :returns: an object with private key and convenience methods

        """
        extra_key_bytes = text_if_str(to_bytes, extra_entropy)
        key_bytes = keccak(os.urandom(32) + extra_key_bytes)
        return self.from_key(key_bytes)

    @classmethod
    def create_private_key(cls, extra_entropy="", return_str=False):
        extra_key_bytes = text_if_str(to_bytes, extra_entropy)
        private_key = keccak(os.urandom(32) + extra_key_bytes)
        if return_str:
            return private_key.hex()
        return private_key
    
    @classmethod
    def hex2str(self, hex_str):
        return bytes.fromhex(hex_str).decode()
    
    @classmethod
    def str2hex(self, string):
        from hexbytes.main import HexBytes
        return HexBytes(string).hex()

    @combomethod
    def from_mnemonic(
        self,
        mnemonic: str,
        passphrase: str = "",
        account_path: str = ETHEREUM_DEFAULT_PATH,
    ) -> 'Key':
        """
        :param str mnemonic: space-separated list of BIP39 mnemonic seed words
        :param str passphrase: Optional passphrase used to encrypt the mnemonic
        :param str account_path: Specify an alternate HD path for deriving the seed
            using BIP32 HD wallet key derivation.
        :return: object with methods for signing and encrypting
        :rtype: Key
        """
        if not self._use_unaudited_hdwallet_features:
            raise AttributeError(
                "The use of the Mnemonic features of Account is disabled by "
                "default until its API stabilizes. To use these features, please "
                "enable them by running `Account.enable_unaudited_hdwallet_features()` "
                "and try again."
            )
        seed = seed_from_mnemonic(mnemonic, passphrase)
        private_key = key_from_seed(seed, account_path)
        key = self._parsePrivateKey(private_key)
        return Key(key)


    def __str__(self):
        return f'Key(address={self.address})'
    

    def __repr__(self):
        return self.__str__()
    

    def resolve_encryption_password(self, password:str=None):
        password = password or self.private_key_string
        if isinstance(password, str):
            password = password.encode()
        password = hashlib.sha256(password).digest()
        return password
    
    def resolve_encryption_data(self, data):
        if not isinstance(data, str):
            data = str(data)
        return data

    def encrypt(self, data, password=None):
        data = self.resolve_encryption_data(data)
        password = self.resolve_encryption_password(password)
        data = data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(password, AES.MODE_CBC, iv)
        encrypted_bytes = base64.b64encode(iv + cipher.encrypt(data.encode()))
        return encrypted_bytes.decode() 

    def decrypt(self, data, password=None):
        data = self.resolve_encryption_data(data)
        password = self.resolve_encryption_password(password)
        data = base64.b64decode(data)
        iv = data[:AES.block_size]
        cipher = AES.new(password, AES.MODE_CBC, iv)
        data =  cipher.decrypt(data[AES.block_size:])
        data = data[:-ord(data[len(data)-1:])].decode('utf-8')
        return data
    
    @classmethod
    def from_key(cls, private_key:str):
        key = Key(private_key)
        print(key.address)
        return key

    
    def save_key(self, name, private_key=None):
        if private_key:
            self.private_key = private_key
        path = c.resolve_path(f'eth/{name}')
        data = {'private_key': self.private_key}
        c.put_json(path, data)
        return self.private_key
    
    def to_dict(self):
        return {
            'address': self.address,
            'private_key': self.private_key_string
        }
    @classmethod
    def from_dict(cls, data):
        print(data['private_key'])
        key = Key.from_key(data['private_key'])
        assert key.address == data['address'], f'{key.address} != {data["address"]}'
        self = key
        return self

    @classmethod
    def get_key_path(cls, name):
        path =  f'{cls.key_storage_path}/{name}.json'
        return c.resolve_path(path)
    
    @classmethod
    def get_key(cls, name, create_if_not_found=True):
        path = cls.get_key_path(name)
        if not os.path.exists(path):
            if create_if_not_found:
                cls.add_key(name)
            else:
                raise Exception(f'Key {name} not found')
        return cls.from_dict(c.get_json(path))
    
    
    @classmethod
    def add_key(self, name, key=None, refresh=False):
        data = Key(key).to_dict()
        path = self.get_key_path(name)
        if os.path.exists(path) and not refresh:
            raise Exception(f'Key {name} already exists')
        c.put_json(path, data)
        return {'status': 'success', 'message': f'Key {name} added'}
    
    @classmethod
    def key_exists(self, name):
        path = self.get_key_path(name)
        print(path)
        return os.path.exists(path)
    
    def load_key(self, name):
        path = self.get_key_path(name)
        data = c.load_json(path)
        self.private_key = data['private_key']
        return {'status': 'success', 'message': f'Key {name} loaded', 'address': self.address}
    
    @classmethod
    def key2path(cls):
        cls.key_storage_path = c.resolve_path(cls.key_storage_path)

        paths = c.ls(cls.key_storage_path)
        key2path = {path.split('/')[-1].split('.')[0]: path for path in paths}
        return key2path
    
    @classmethod
    def keys(cls, search=None):
        keys = list(cls.key2path().keys())
        if search:
            keys = list(filter(lambda k: search in k, keys))
        return keys

    @classmethod
    def remove_key(cls, name):
        return os.remove(cls.get_key_path(name))
