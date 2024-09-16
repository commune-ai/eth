import os
from copy import deepcopy
from typing import *
import commune as c
from .key import Key

class eth(c.Module):

    def __init__(self, 
                 network: str = 'local', 
                 key : str = 'base'
                 ):
                 
        self.set_network(network)
        self.set_key(key)

    def compile(self):
        # compile smart contracts in compile
        return c.cmd('npx hardhat compile')
    
    @classmethod
    def get_key(cls, key:str):
        return Key.get_key(key)
    
    @classmethod
    def add_key(cls,name, key=None):
        return Key.add_key(name, key)
    
    @classmethod
    def keys(cls):
        return Key.keys()

    @property
    def interfaces(self):
        interfaces = list(filter(lambda f: f.startswith('interfaces'), self.artifacts()))
        return list(map(lambda f:os.path.dirname(f.replace('interfaces/', '')), interfaces))

    def resolve_key(self, key):
        if isinstance(key, str):
            from .key import Key
            key = Key(key)
        if key == None:
            key = self.key
        return key

    def set_key(self, key:str):
        self.key = Key.get_key(key)

    def resolve_network(self, network):
        if network == None:
            network = self.network
        return network

    def set_network(self, network:str='local') -> 'Web3':
        self.network = network

    @property
    def client(self):
        return  self.get_client(self.network)

    @property
    def network_state(self):
        return c.load_yaml(self.dirpath() + '/networks.yaml')

    @property
    def networks(self):
        return list(self.network_state.keys())

    @property
    def available_networks(self):
        return self.get_available_networks()

    def get_urls(self, network:str ) -> List[str]:
        urls = self.network_state[network]['url']
        if isinstance(urls, str):
            urls = [urls]
        return urls

    def get_url(self, network:str='local' ) -> str:
        return self.get_urls(network)[0]
    
    def get_client(self, network: str) -> 'Web3':
        network_url = self.get_url(network)
        from web3.main import Web3
        if network_url.startswith("http"):
            from web3.providers import HTTPProvider
            provider =  HTTPProvider(network_url)
        elif network_url.startswith("ws"):
            from web3.providers import WebsocketProvider
            provider =  WebsocketProvider(network_url)
        else:
            raise AssertionError(f"Invalid network url: {network_url}")
        conn =  Web3(provider)
        if conn.eth.chain_id == 4:
            conn.middleware_onion.inject(conn.middleware.geth_poa_middleware, layer=0)
        return conn
    
    def is_valid_address(self, address:str) -> bool:
        return self.client.is_address(address)

    def resolve_address(self, key):
        if self.is_valid_address(key):
            return key
        if hasattr(key, 'address'):
            address = key.address
        else:
            key = self.resolve_key(key)
            address = key.address
        return address

    def get_transaction_count(self, key=None):
        address = self.resolve_address(key)
        return self.client.eth.get_transaction_count(address)
    
    nonce = get_transaction_count

    def gas_price(self):
        return self.client.eth.generate_gas_price() or 0

    def tx_metadata(self, key=None) -> Dict[str, Union[int, str, bytes]]:
        key = self.resolve_key(key)
        return {
            'from': key.address,
            'nonce': self.get_transaction_count(key),
            'gasPrice':self.gas_price(),
            }
    
    def send_tx(self, tx, key = None) -> Dict:
        key = self.resolve_key(key)
        rawTransaction = self.sign_tx(tx=tx)    
        tx_hash = self.client.eth.send_raw_transaction(rawTransaction)
        tx_receipt = self.client.eth.wait_for_transaction_receipt(tx_hash)
        return tx_receipt.__dict__

    def sign_tx( self, tx: Dict, key=None ) -> 'HexBytes':
        key = self.resolve_key(key)
        tx['nonce'] = self.get_transaction_count(key)
        tx["gasPrice"] = self.gas_price()
        signed_tx = self.client.eth.sign_transaction(tx, key.private_key)
        return signed_tx.rawTransaction

    def get_balance(self,address:str=None, token:str=None, ):
        address = self.resolve_address(address)
        balance = self.client.eth.get_balance(address)
        return balance
    def ganache(self, port:int=8545, balance=100, remote=1):


        if remote:
            return self.remote_fn('ganache', 
                                  name = 'ganache',
                                  kwargs={'port':port, 'balance':balance, 'remote':False})

        import os
        import subprocess
        from .key import Key

        if c.port_used(port):
            c.kill_port(port)

        # Check if Ganache CLI is installed
        try:
            subprocess.run(["ganache-cli", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            # Install Ganache CLI if it's not present
            print("Installing Ganache CLI...")
            os.system("npm install -g ganache-cli")
        
        # Get all keys from storage
        keys = Key.keys()
        
        # Prepare account strings for Ganache
        account_strings = []
        for key_name in keys:
            key = Key.get_key(key_name)
            private_key_str = key.private_key_string
            balance_wei = str(int(balance) * 10**18)
            account_strings.append(f'"{private_key_str},{balance_wei}"')
        
        # Join account strings
        accounts_param = ' '.join([f'--account={acc}' for acc in account_strings])
        
        # Start Ganache CLI with all accounts funded
        cmd = f'ganache-cli -p {port} {accounts_param}'
        print(f"Starting Ganache with command: {cmd}")
        os.system(cmd)
    localnet = ganache

    def tree(self):
        dirpath = self.dirpath()
        modules = c.get_tree(dirpath)
        return modules
    
    def get_module(self, module:str):
        return c.get_module('eth.'+module)

Module = eth