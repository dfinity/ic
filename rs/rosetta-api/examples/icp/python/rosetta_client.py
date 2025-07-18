import json

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key


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

    # Default currency information for the Internet Computer
    DEFAULT_CURRENCY_SYMBOL = "ICP"
    DEFAULT_CURRENCY_DECIMALS = 8

    def __init__(self, node_address, private_key_path=None, signature_type="ecdsa"):
        """
        Initialize the Rosetta client.

        Args:
            node_address (str): The URL of the Rosetta API endpoint.
            private_key_path (str, optional): Path to the private key file. Defaults to None.
            signature_type (str, optional): Type of signature to use. Defaults to "ecdsa".

        """
        self.node_address = node_address.rstrip("/")
        self.network = self.get_network_list()[0]["network"]
        self.signature_type = signature_type

        # Initialize with default currency values
        self.currency_symbol = self.DEFAULT_CURRENCY_SYMBOL
        self.currency_decimals = self.DEFAULT_CURRENCY_DECIMALS

        # Try to get actual currency info from the blockchain
        try:
            currency_info = self._get_currency_info()
            if currency_info:
                self.currency_symbol = currency_info["symbol"]
                self.currency_decimals = currency_info["decimals"]
        except Exception as e:
            print(f"Warning: Unable to retrieve currency information from the blockchain. Using defaults. Error: {e}")

        self._set_up_crypto(private_key_path)

    def _get_currency_info(self):
        """
        Get currency information from the blockchain by examining recent blocks.

        Returns:
            dict: Currency information with symbol and decimals, or None if not found.

        """
        try:
            # Try to get currency info from the last block
            last_block = self.get_last_block()

            # Check if the block has transactions
            if "block" in last_block and "transactions" in last_block["block"] and last_block["block"]["transactions"]:
                # Look through all transactions and operations for an amount field with currency info
                for tx in last_block["block"]["transactions"]:
                    if "operations" in tx:
                        for op in tx["operations"]:
                            if "amount" in op and "currency" in op["amount"]:
                                return op["amount"]["currency"]

            # If not found in last block, try a few more blocks
            current_index = last_block["block"]["block_identifier"]["index"]
            for i in range(1, 6):  # Try up to 5 previous blocks
                try:
                    block = self.get_block(current_index - i)
                    if "block" in block and "transactions" in block["block"] and block["block"]["transactions"]:
                        for tx in block["block"]["transactions"]:
                            if "operations" in tx:
                                for op in tx["operations"]:
                                    if "amount" in op and "currency" in op["amount"]:
                                        return op["amount"]["currency"]
                except Exception:
                    continue

            # If still not found, try network options which might contain currency info
            options = self.get_network_options()
            if "allow" in options and "currency" in options["allow"]:
                return options["allow"]["currency"]

            return None
        except Exception as e:
            print(f"Error retrieving currency information: {e}")
            return None

    def _set_up_crypto(self, private_key_path):
        """
        Set up the cryptographic keys for signing transactions.

        Args:
            private_key_path (str, optional): Path to the private key file.

        """
        if private_key_path is None:
            return
        with open(private_key_path, "rb") as pem_file:
            self.private_key = load_pem_private_key(pem_file.read(), password=None, backend=default_backend())

        # Derive curve type and public key based on key type
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            curve = self.private_key.curve
            # Currently supporting secp256k1
            self.curve_type = "secp256k1" if isinstance(curve, ec.SECP256K1) else curve.name

            # Compute the compressed public key for ECDSA keys
            public_numbers = self.private_key.public_key().public_numbers()
            prefix = "02" if public_numbers.y % 2 == 0 else "03"
            self.compressed_public_key = prefix + format(public_numbers.x, "064x")

        elif isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            self.curve_type = "edwards25519"
            # For Ed25519, use the raw public key bytes
            public_key_bytes = self.private_key.public_key().public_bytes_raw()
            self.compressed_public_key = public_key_bytes.hex()
            # Ed25519 uses EdDSA signature scheme
            self.signature_type = "ed25519"
        else:
            raise ValueError("Unsupported key type. Supported types: secp256k1, edwards25519")

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

    def _send_with_neuron_check(self, command, payload, verbose=False):
        """
        Send a request to the Rosetta API with special handling for neuron-related errors.

        Args:
            command (str): The API command/endpoint to call.
            payload (dict): The request payload.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The response from the API or an error message in a structured format.

        """
        url = f"{self.node_address}/{command}"
        if verbose:
            print(f"Sending {command} with payload:\n{json.dumps(payload, indent=2)}")

        response = requests.post(url, json=payload)

        if response.status_code != 200:
            error_text = response.text
            # Check if this is a "No neuron found" error
            if "No neuron found for subaccount" in error_text:
                if verbose:
                    print("No neuron found for the specified account")
                return {
                    "status": "error",
                    "error_type": "neuron_not_found",
                    "message": "No neuron found for the specified account.",
                    "details": error_text,
                }
            else:
                raise Exception(f"Error: {error_text}")

        ret = response.json()
        if verbose:
            print(f"Received response:\n{json.dumps(ret, indent=2)}")
        return ret

    def get_account_identifier(self, public_key=None, neuron_index=None, verbose=False):
        """
        Derive the account identifier from the compressed public key.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            str: The account identifier.

        """

        if not public_key and not self.compressed_public_key:
            raise Exception("Either public_key or compressed_public_key must be provided to get_account_identifier")

        public_key = (
            public_key if public_key else {"hex_bytes": self.compressed_public_key, "curve_type": self.curve_type}
        )

        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "public_key": public_key,
        }
        if neuron_index is not None:
            payload["metadata"] = {"account_type": "neuron", "neuron_index": neuron_index}
        res = self._send("construction/derive", payload, verbose=verbose)
        return res["account_identifier"]["address"]

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
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "public_keys": [{"hex_bytes": self.compressed_public_key, "curve_type": self.curve_type}],
            "operations": operations,
        }
        payloads_response = self._send("construction/payloads", payloads_payload, verbose=verbose)
        signatures = []
        for payload in payloads_response["payloads"]:
            signature_hex = self._sign_payload(payload["hex_bytes"])
            signatures.append(
                {
                    "hex_bytes": signature_hex,
                    "signing_payload": {
                        "account_identifier": {"address": account_id},
                        "hex_bytes": payload["hex_bytes"],
                        "signature_type": self.signature_type,
                    },
                    "public_key": {"hex_bytes": self.compressed_public_key, "curve_type": self.curve_type},
                    "signature_type": self.signature_type,
                }
            )
        combine_request = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "unsigned_transaction": payloads_response["unsigned_transaction"],
            "signatures": signatures,
        }
        combine_response = self._send("construction/combine", combine_request, verbose=verbose)
        submit_request = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "signed_transaction": combine_response["signed_transaction"],
        }
        return self._send("construction/submit", submit_request, verbose=verbose)

    def _sign_payload(self, hex_bytes):
        """
        Sign a payload using the appropriate algorithm for the key type.

        Args:
            hex_bytes (str): The hex-encoded payload to sign.

        Returns:
            str: The hex-encoded signature.

        """
        payload_bytes = bytes.fromhex(hex_bytes)

        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            # ECDSA signing for secp256k1
            der_sig = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(der_sig)
            r_bytes = r.to_bytes(32, byteorder="big")
            s_bytes = s.to_bytes(32, byteorder="big")
            return (r_bytes + s_bytes).hex()

        elif isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            # Ed25519 signing
            signature = self.private_key.sign(payload_bytes)
            return signature.hex()

        else:
            raise ValueError("Unsupported key type for signing")

    def get_network_list(self, verbose=False):
        """
        Get a list of available networks.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            list: List of available networks.

        """
        payload = {}
        return self._send("network/list", payload, verbose=verbose)["network_identifiers"]

    def get_network_status(self, verbose=False):
        """
        Get the current status of the network.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Network status information.

        """
        payload = {"network_identifier": {"blockchain": "Internet Computer", "network": self.network}}
        return self._send("network/status", payload, verbose=verbose)

    def get_network_options(self, verbose=False):
        """
        Get the options supported by the network.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Network options information.

        """
        payload = {"network_identifier": {"blockchain": "Internet Computer", "network": self.network}}
        return self._send("network/options", payload, verbose=verbose)

    def get_last_block(self, verbose=False):
        """
        Get the latest block from the ledger.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The latest block information.

        """
        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "block_identifier": {},
        }
        return self._send("block", payload, verbose=verbose)

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
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals},
                },
            },
            {
                "operation_identifier": {"index": 1},
                "type": "TRANSACTION",
                "account": {"address": to_account},
                "amount": {
                    "value": str(amount),
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals},
                },
            },
            {
                "operation_identifier": {"index": 1},
                "type": "FEE",
                "account": {"address": from_account},
                "amount": {
                    "value": f"-{str(fee)}",
                    "currency": {"symbol": self.currency_symbol, "decimals": self.currency_decimals},
                },
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
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "account_identifier": {"address": address},
        }
        return self._send("account/balance", payload, verbose=verbose)

    def get_neuron_balance(self, address, neuron_index=0, public_key=None, verbose=False):
        """
        Fetch the balance of a staked neuron.

        Args:
            address (str): The neuron's account identifier.
            neuron_index (int, optional): The neuron index. Defaults to 0.
            public_key (dict): The public key information containing hex_bytes and curve_type.
                Example: {"hex_bytes": "ba5242d02642aede88a5f9fe82482a9fd0b6dc25f38c729253116c6865384a9d",
                          "curve_type": "edwards25519"}
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The neuron balance information or an error status if no neuron is found.

        """
        if public_key is None:
            raise ValueError("public_key is required for neuron balance queries")

        metadata = {"account_type": "neuron", "neuron_index": neuron_index, "public_key": public_key}

        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "account_identifier": {"address": address},
            "metadata": metadata,
        }
        return self._send_with_neuron_check("account/balance", payload, verbose=verbose)

    def get_block(self, index=None, verbose=False):
        """
        Get a block by index.

        Args:
            index (int, optional): The block index. If None, gets the latest block. Defaults to None.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The block information.

        """
        block_identifier = {} if index is None else {"index": index}
        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "block_identifier": block_identifier,
        }
        return self._send("block", payload, verbose=verbose)

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
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "block_identifier": {"index": block_index},
            "transaction_identifier": {"hash": transaction_hash},
        }
        return self._send("block/transaction", payload, verbose=verbose)

    def search_transactions(
        self, address=None, transaction_hash=None, operation_type=None, start_index=None, limit=10, verbose=False
    ):
        """
        Search for transactions related to an address, by hash, or by operation type.

        Args:
            address (str, optional): The account identifier to search for. Defaults to None.
            transaction_hash (str, optional): The transaction hash to search for. Defaults to None.
            operation_type (str, optional): The operation type to search for (e.g., TRANSFER, MINT). Defaults to None.
            start_index (int, optional): The starting index for pagination. Defaults to None.
            limit (int, optional): The maximum number of transactions to return. Defaults to 10.
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The search results.

        """
        payload = {"network_identifier": {"blockchain": "Internet Computer", "network": self.network}, "limit": limit}

        if address:
            payload["account_identifier"] = {"address": address}

        if transaction_hash:
            payload["transaction_identifier"] = {"hash": transaction_hash}

        if operation_type:
            payload["type"] = operation_type

        if start_index:
            payload["offset"] = start_index

        return self._send("search/transactions", payload, verbose=verbose)

    def list_known_neurons(self, verbose=False):
        """
        List all publicly known neurons on the Network Nervous System.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Information about known neurons.

        """
        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "method_name": "list_known_neurons",
            "parameters": {},
        }
        return self._send("call", payload, verbose=verbose)

    def get_pending_proposals(self, verbose=False):
        """
        List all currently pending proposals on the Network Nervous System.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Information about pending proposals.

        """
        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "method_name": "get_pending_proposals",
            "parameters": {},
        }
        return self._send("call", payload, verbose=verbose)

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
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "method_name": "get_proposal_info",
            "parameters": {"proposal_id": proposal_id},
        }
        return self._send("call", payload, verbose=verbose)

    def get_minimum_dissolve_delay(self, verbose=False):
        """
        Returns the minimum dissolve delay of a neuron that still allows it to vote.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Information about minimum dissolve delay of a neuron.

        """
        payload = {
            "network_identifier": {"blockchain": "Internet Computer", "network": self.network},
            "method_name": "get_minimum_dissolve_delay",
            "parameters": {},
        }
        return self._send("call", payload, verbose=verbose)
