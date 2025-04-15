import json
import requests
import hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

class RosettaClient:
    """
    A client for interacting with the Internet Computer Rosetta API.
    
    This class provides methods to perform common operations through the Rosetta API,
    including fetching balances, transferring ICP, reading blocks, and interacting
    with the Network Nervous System (NNS) for governance.
    
    Attributes:
        node_address (str): The URL of the Rosetta API endpoint.
        network (str): The network identifier for the Internet Computer.
        currency_symbol (str): The symbol of the currency (e.g., 'ICP').
        currency_decimals (int): The number of decimal places for the currency.
        private_key (object): Optional private key for signing transactions.
        compressed_public_key (str): Compressed public key derived from the private key.
        curve_type (str): The curve type for the cryptographic keys.
    """
    
    def __init__(self, node_address, private_key_path=None, signature_type="ecdsa"):
        """
        Initialize the Rosetta client.
        
        Args:
            node_address (str): The URL of the Rosetta API endpoint.
            private_key_path (str, optional): Path to the private key file. Defaults to None.
            signature_type (str, optional): Type of signature to use. Defaults to "ecdsa".
        """
        self.node_address = node_address.rstrip('/')
        self.network = self.get_network_list()[0]['network']
        last_block = self.get_last_block()
        currency = last_block['block']['transactions'][0]['operations'][0]['amount']['currency']
        self.signature_type = signature_type
        self.currency_symbol = currency['symbol']
        self.currency_decimals = currency['decimals']
        self._set_up_crypto(private_key_path)

    def _set_up_crypto(self, private_key_path):
        """
        Set up the cryptographic keys for signing transactions.
        
        Args:
            private_key_path (str, optional): Path to the private key file.
        """
        if private_key_path is None:
            return
        with open(private_key_path, 'rb') as pem_file:
                self.private_key = load_pem_private_key(pem_file.read(), password=None, backend=default_backend())
        # Derive curve type automatically.
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            curve = self.private_key.curve
            # Currently only supporting secp256k1.
            self.curve_type = "secp256k1" if isinstance(curve, ec.SECP256K1) else curve.name
        else:
            raise ValueError("Unsupported key type")

        # Compute the compressed public key.
        public_numbers = self.private_key.public_key().public_numbers()
        prefix = '02' if public_numbers.y % 2 == 0 else '03'
        self.compressed_public_key = prefix + format(public_numbers.x, '064x')
    
    def _send(self, command, payload, verbose=False):
        """
        Send a request to the Rosetta API.
        
        Args:
            command (str): The API command/endpoint to call.
            payload (dict): The request payload.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The response from the API.
            
        Raises:
            Exception: If the API request fails.
        """
        url = f"{self.node_address}/{command}"
        if verbose:
            print(f"Sending {command} with payload:\n{json.dumps(payload, indent=2)}")
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            raise Exception(f"Error: {response.text}")
        ret = response.json()
        if verbose:
            print(f"Received response:\n{json.dumps(ret, indent=2)}")
        return ret

    def get_account_identifier(self, verbose=False):
        """
        Derive the account identifier from the compressed public key.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            str: The account identifier.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "public_key": {
                "hex_bytes": self.compressed_public_key,
                "curve_type": self.curve_type
            }
        }
        res = self._send('construction/derive', payload, verbose=verbose)
        return res['account_identifier']['address']
    
    def _submit_operations(self, operations, verbose=False):
        """
        Submit operations (like transfers) to the network.
        
        Args:
            operations (list): The operations to submit.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The response from the API.
        """
        account_id = self.get_account_identifier(verbose=verbose)
        payloads_payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "public_keys": [{
                "hex_bytes": self.compressed_public_key,
                "curve_type": self.curve_type
            }],
            "operations": operations
        }
        payloads_response = self._send('construction/payloads', payloads_payload, verbose=verbose)
        signatures = []
        for payload in payloads_response['payloads']:
            # Sign the payload using cryptography and convert DER to raw (r||s)
            der_sig = self.private_key.sign(
                bytes.fromhex(payload['hex_bytes']),
                ec.ECDSA(hashes.SHA256())
            )
            r, s = utils.decode_dss_signature(der_sig)
            r_bytes = r.to_bytes(32, byteorder="big")
            s_bytes = s.to_bytes(32, byteorder="big")
            raw_sig = (r_bytes + s_bytes).hex()
            signatures.append({
                "hex_bytes": raw_sig,
                "signing_payload": {
                    "account_identifier": {"address": account_id},
                    "hex_bytes": payload['hex_bytes'],
                    "signature_type": self.signature_type,
                },
                "public_key": {
                    "hex_bytes": self.compressed_public_key,
                    "curve_type": self.curve_type
                },
                "signature_type": self.signature_type
            })
        combine_request = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "unsigned_transaction": payloads_response['unsigned_transaction'],
            "signatures": signatures
        }
        combine_response = self._send('construction/combine', combine_request, verbose=verbose)
        submit_request = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "signed_transaction": combine_response['signed_transaction']
        }
        return self._send('construction/submit', submit_request, verbose=verbose)
    
    def get_network_list(self, verbose=False):
        """
        Get a list of available networks.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            list: List of available networks.
        """
        payload = {}
        return self._send('network/list', payload, verbose=verbose)['network_identifiers']

    def get_network_status(self, verbose=False):
        """
        Get the current status of the network.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: Network status information.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            }
        }
        return self._send('network/status', payload, verbose=verbose)

    def get_network_options(self, verbose=False):
        """
        Get the options supported by the network.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: Network options information.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            }
        }
        return self._send('network/options', payload, verbose=verbose)

    def get_last_block(self, verbose=False):
        """
        Get the latest block from the ledger.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The latest block information.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "block_identifier": {}
        }
        return self._send('block', payload, verbose=verbose)

    def transfer(self, to_account, amount, fee, verbose=False):
        """
        Transfer ICP from the account associated with the loaded private key to another account.
        
        Args:
            to_account (str): The recipient's account identifier.
            amount (int): The amount to transfer in e8s (1 ICP = 100,000,000 e8s).
            fee (int): The fee to pay for the transaction.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The response from the API.
        """
        from_account = self.get_account_identifier(verbose=verbose)
        operations = [
            {
                "operation_identifier": {"index": 0},
                "type": "TRANSACTION",
                "account": {"address": from_account},
                "amount": {
                    "value": f"-{amount}",
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            },
            {
                "operation_identifier": {"index": 1},
                "type": "TRANSACTION",
                "account": {"address": to_account},
                "amount": {
                    "value": str(amount),
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            },
            {
                "operation_identifier": {"index": 1},
                "type": "FEE",
                "account": {"address": from_account},
                "amount": {
                    "value": f"-{str(fee)}",
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            },
            
        ]
        return self._submit_operations(operations, verbose=verbose)
    
    def get_balance(self, address=None, verbose=False):
        """
        Get the balance of an account.
        
        Args:
            address (str, optional): The account identifier. If None, uses the current account. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The account balance information.
        """
        if address is None:
            address = self.get_account_identifier(verbose=verbose)
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "account_identifier": {
                "address": address
            }
        }
        return self._send('account/balance', payload, verbose=verbose)
    
    def get_neuron_balance(self, address, neuron_index=0, public_key=None, verbose=False):
        """
        Fetch the balance of a staked neuron.
        
        Args:
            address (str): The neuron's account identifier.
            neuron_index (int, optional): The neuron index. Defaults to 0.
            public_key (dict, optional): The public key information. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The neuron balance information.
        """
        metadata = {
            "account_type": "neuron",
            "neuron_index": neuron_index
        }
        
        # Add public key if provided
        if public_key:
            metadata["public_key"] = public_key
            
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "account_identifier": {
                "address": address
            },
            "metadata": metadata
        }
        return self._send('account/balance', payload, verbose=verbose)
    
    def get_block(self, index=None, verbose=False):
        """
        Get a block by index.
        
        Args:
            index (int, optional): The block index. If None, gets the latest block. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The block information.
        """
        block_identifier = {} if index is None else {
            "index": index
        }
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "block_identifier": block_identifier
        }
        return self._send('block', payload, verbose=verbose)
    
    def get_transaction(self, block_index, transaction_hash, verbose=False):
        """
        Fetch a specific transaction from a block.
        
        Args:
            block_index (int): The block index.
            transaction_hash (str): The transaction hash.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The transaction information.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "block_identifier": {
                "index": block_index
            },
            "transaction_identifier": {
                "hash": transaction_hash
            }
        }
        return self._send('block/transaction', payload, verbose=verbose)
    
    def search_transactions(self, address=None, start_index=None, limit=10, verbose=False):
        """
        Search for transactions related to an address.
        
        Args:
            address (str, optional): The account identifier to search for. Defaults to None.
            start_index (int, optional): The starting index for pagination. Defaults to None.
            limit (int, optional): The maximum number of transactions to return. Defaults to 10.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The search results.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "operator": "or",
            "limit": limit
        }
        
        if address:
            payload["account_identifier"] = {"address": address}
            
        if start_index:
            payload["offset"] = start_index
            
        return self._send('search/transactions', payload, verbose=verbose)
    
    def list_known_neurons(self, verbose=False):
        """
        List all publicly known neurons on the Network Nervous System.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: Information about known neurons.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "method_name": "list_known_neurons",
            "parameters": {}
        }
        return self._send('call', payload, verbose=verbose)
    
    def get_pending_proposals(self, verbose=False):
        """
        List all currently pending proposals on the Network Nervous System.
        
        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: Information about pending proposals.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "method_name": "get_pending_proposals",
            "parameters": {}
        }
        return self._send('call', payload, verbose=verbose)
    
    def get_proposal_info(self, proposal_id, verbose=False):
        """
        Get information about a specific proposal on the Network Nervous System.
        
        Args:
            proposal_id (int): The ID of the proposal to retrieve.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: Detailed information about the proposal.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "method_name": "get_proposal_info",
            "parameters": {
                "proposal_id": proposal_id
            }
        }
        return self._send('call', payload, verbose=verbose)
    
