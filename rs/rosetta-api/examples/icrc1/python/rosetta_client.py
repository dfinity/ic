import json
import requests
import hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

class RosettaClient:
    """
    A client for interacting with the ICRC-1 Rosetta API on the Internet Computer.
    
    This class provides methods to perform common operations through the Rosetta API,
    including fetching balances, transferring tokens, and reading blocks from ICRC-1 ledgers.
    
    Attributes:
        node_address (str): The URL of the Rosetta API endpoint.
        network (str): The network identifier (canister ID) for the ICRC-1 ledger.
        currency_symbol (str): The symbol of the currency (e.g., 'ckBTC', 'CHAT').
        currency_decimals (int): The number of decimal places for the currency.
        private_key (object): Optional private key for signing transactions.
        compressed_public_key (str): Compressed public key derived from the private key.
        curve_type (str): The curve type for the cryptographic keys.
    """
    
    def __init__(self, node_address, canister_id, private_key_path=None, signature_type="ecdsa"):
        """
        Initialize the Rosetta client.
        
        Args:
            node_address (str): The URL of the Rosetta API endpoint.
            canister_id (str): The canister ID of the ICRC-1 ledger (network identifier).
            private_key_path (str, optional): Path to the private key file. Defaults to None.
            signature_type (str, optional): Type of signature to use. Defaults to "ecdsa".
        """
        self.node_address = node_address.rstrip('/')
        self.network = canister_id
        self.signature_type = signature_type
        
        # Try to get currency information from the latest block
        try:
            last_block = self.get_block()
            currency = last_block['block']['transactions'][0]['operations'][0]['amount']['currency']
            self.currency_symbol = currency['symbol']
            self.currency_decimals = currency['decimals']
        except (KeyError, IndexError, Exception) as e:
            # Default values if unable to determine from block
            self.currency_symbol = "ICRC1"
            self.currency_decimals = 8
            
        self._set_up_crypto(private_key_path)

    def _set_up_crypto(self, private_key_path):
        """
        Set up the cryptographic keys for signing transactions.
        
        Args:
            private_key_path (str, optional): Path to the private key file.
        """
        if private_key_path is None:
            self.private_key = None
            self.compressed_public_key = None
            self.curve_type = None
            return
            
        with open(private_key_path, 'rb') as pem_file:
            self.private_key = load_pem_private_key(pem_file.read(), password=None, backend=default_backend())
            
        # Derive curve type automatically
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            curve = self.private_key.curve
            # Currently only supporting secp256k1
            self.curve_type = "secp256k1" if isinstance(curve, ec.SECP256K1) else curve.name
        else:
            raise ValueError("Unsupported key type")

        # Compute the compressed public key
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

    def get_principal_identifier(self, principal, subaccount=None, verbose=False):
        """
        Create the account identifier object from principal and optional subaccount.
        
        In ICRC-1, accounts are identified by a principal ID and an optional subaccount.
        
        Args:
            principal (str): Principal identifier
            subaccount (str, optional): Subaccount in hex format
            verbose (bool, optional): Whether to print verbose output
            
        Returns:
            dict: Account identifier object with address and optional sub_account
        """
        account_id = {"address": principal}
        
        if subaccount:
            account_id["sub_account"] = {"address": subaccount}
            
        return account_id
        
    # Maintain backward compatibility
    get_account_identifier = get_principal_identifier
        
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

    def get_block(self, block_index=None, block_hash=None, verbose=False):
        """
        Get a specific block by index or hash.
        
        Args:
            block_index (int, optional): The block index/height. Defaults to None.
            block_hash (str, optional): The block hash. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The block information.
        """
        block_identifier = {}
        
        if block_index is not None:
            block_identifier["index"] = block_index
            
        if block_hash is not None:
            block_identifier["hash"] = block_hash
            
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "block_identifier": block_identifier
        }
        return self._send('block', payload, verbose=verbose)
    
    def get_balance(self, principal=None, subaccount=None, verbose=False):
        """
        Get the balance of a principal and optional subaccount.
        
        Args:
            principal (str, optional): The principal identifier. Defaults to None.
            subaccount (str, optional): The subaccount in hex format. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The balance information.
        """
        if principal is None:
            raise ValueError("Principal is required for balance queries")
        
        account_identifier = self.get_principal_identifier(principal, subaccount)
        
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "account_identifier": account_identifier
        }
        return self._send('account/balance', payload, verbose=verbose)
    
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
    
    def search_transactions(self, principal=None, subaccount=None, limit=10, offset=None, 
                          transaction_hash=None, operation_type=None, max_block=None, verbose=False):
        """
        Search for transactions related to a principal.
        
        Args:
            principal (str, optional): The principal identifier. Defaults to None.
            subaccount (str, optional): The subaccount in hex format. Defaults to None.
            limit (int, optional): Maximum number of transactions to return. Defaults to 10.
            offset (int, optional): Offset for pagination. Defaults to None.
            transaction_hash (str, optional): Hash of a specific transaction to find. Defaults to None.
            operation_type (str, optional): Type of operation to filter by (e.g., "TRANSFER", "MINT", "BURN", "APPROVE"). Defaults to None.
            max_block (int, optional): The maximum block index to search up to. Defaults to None (latest block).
            verbose (bool, optional): Whether to print verbose output. Defaults to False.
            
        Returns:
            dict: The search results.
        """
        payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "limit": limit
        }
        
        # Add account identifier if principal is provided
        if principal:
            account_identifier = self.get_principal_identifier(principal, subaccount)
            payload["account_identifier"] = account_identifier
            
        # Add pagination offset if provided
        if offset is not None:
            payload["offset"] = offset
        
        # Add transaction identifier if hash is provided
        if transaction_hash:
            payload["transaction_identifier"] = {
                "hash": transaction_hash
            }
        
        # Add operation type if provided
        if operation_type:
            payload["type"] = operation_type
            
        # Add max block if provided
        if max_block is not None:
            payload["max_block"] = max_block
        
        return self._send('search/transactions', payload, verbose=verbose)
    
    def _prepare_operations_for_transfer(self, from_principal, from_subaccount, 
                                       to_principal, to_subaccount, 
                                       amount, fee):
        """
        Prepare operations for a transfer transaction.
        
        Args:
            from_principal (str): Sender's principal identifier
            from_subaccount (str, optional): Sender's subaccount
            to_principal (str): Recipient's principal identifier
            to_subaccount (str, optional): Recipient's subaccount
            amount (int): Amount to transfer
            fee (int): Fee to pay
            
        Returns:
            list: Operations to submit
        """
        from_account = self.get_principal_identifier(from_principal, from_subaccount)
        to_account = self.get_principal_identifier(to_principal, to_subaccount)
        
        operations = [
            {
                "operation_identifier": {"index": 0},
                "type": "TRANSFER",
                "account": from_account,
                "amount": {
                    "value": f"-{amount}",
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            },
            {
                "operation_identifier": {"index": 1},
                "type": "TRANSFER",
                "account": to_account,
                "amount": {
                    "value": str(amount),
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            },
            {
                "operation_identifier": {"index": 2},
                "type": "FEE",
                "account": from_account,
                "amount": {
                    "value": f"-{fee}",
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals}
                }
            }
        ]
        return operations

    def _sign_payload(self, payload_bytes):
        """
        Sign a payload using the private key.
        
        Args:
            payload_bytes (bytes): The payload to sign
            
        Returns:
            str: The signature in hex format
        """
        if not self.private_key:
            raise ValueError("Private key is required for signing")
            
        # Sign the payload and convert DER to raw (r||s)
        der_sig = self.private_key.sign(
            payload_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        r, s = utils.decode_dss_signature(der_sig)
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        return (r_bytes + s_bytes).hex()

    def transfer(self, from_principal, to_principal, amount, fee, 
                from_subaccount=None, to_subaccount=None, memo=None, verbose=False):
        """
        Transfer tokens between principals.
        
        Args:
            from_principal (str): Sender's principal identifier
            to_principal (str): Recipient's principal identifier
            amount (int): Amount to transfer
            fee (int): Fee to pay
            from_subaccount (str, optional): Sender's subaccount
            to_subaccount (str, optional): Recipient's subaccount
            memo (list, optional): Optional memo field
            verbose (bool, optional): Whether to print verbose output
            
        Returns:
            dict: The response from the API
        """
        if not self.private_key:
            raise ValueError("Private key is required for transfers")
            
        operations = self._prepare_operations_for_transfer(
            from_principal, from_subaccount,
            to_principal, to_subaccount,
            amount, fee
        )
        
        # Prepare metadata
        metadata = {}
        if memo:
            metadata["memo"] = memo
            
        # Prepare payloads
        payloads_payload = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "operations": operations,
            "metadata": metadata if metadata else None,
            "public_keys": [{
                "hex_bytes": self.compressed_public_key,
                "curve_type": self.curve_type
            }]
        }
        
        if not payloads_payload["metadata"]:
            del payloads_payload["metadata"]
            
        payloads_response = self._send('construction/payloads', payloads_payload, verbose=verbose)
        
        # Sign the payloads
        signatures = []
        for payload in payloads_response['payloads']:
            signature = self._sign_payload(bytes.fromhex(payload['hex_bytes']))
            signatures.append({
                "hex_bytes": signature,
                "signing_payload": {
                    "account_identifier": self.get_principal_identifier(from_principal, from_subaccount),
                    "hex_bytes": payload['hex_bytes'],
                    "signature_type": self.signature_type,
                },
                "public_key": {
                    "hex_bytes": self.compressed_public_key,
                    "curve_type": self.curve_type
                },
                "signature_type": self.signature_type
            })
            
        # Combine signatures with unsigned transaction
        combine_request = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "unsigned_transaction": payloads_response['unsigned_transaction'],
            "signatures": signatures
        }
        combine_response = self._send('construction/combine', combine_request, verbose=verbose)
        
        # Submit the signed transaction
        submit_request = {
            "network_identifier": {
                "blockchain": "Internet Computer",
                "network": self.network
            },
            "signed_transaction": combine_response['signed_transaction']
        }
        return self._send('construction/submit', submit_request, verbose=verbose) 