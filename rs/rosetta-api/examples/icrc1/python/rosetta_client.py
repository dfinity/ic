import base64  # For base32 encoding
import hashlib
import json
import zlib  # Add zlib import for crc32

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key


class RosettaClient:
    """
    A client for interacting with the ICRC-1 Rosetta API on the Internet Computer.

    This class provides methods to perform common operations through the Rosetta API,
    including fetching balances, transferring tokens, and reading blocks from ICRC-1 ledgers.

    Attributes:
        node_address (str): The URL of the Rosetta API endpoint.
        network (str): The blockchain network identifier.
        canister_id (str): The ICRC-1 canister identifier.
        private_key: The private key for signing transactions.

    """

    def __init__(self, node_address, canister_id):
        """
        Initialize the Rosetta client.

        Args:
            node_address (str): The URL of the Rosetta API endpoint.
            canister_id (str): The ICRC-1 canister identifier.

        """
        self.node_address = node_address
        self.canister_id = canister_id
        self.private_key = None

        # Get network information to use in subsequent requests
        network_list = self.list_networks(verbose=False)
        if not network_list:
            raise Exception("Could not determine network information")

        # Default to the first network we find
        self.network = {"blockchain": network_list[0]["blockchain"], "network": network_list[0]["network"]}

    def setup_keys(self, private_key_path=None):
        """
        Set up the cryptographic keys for signing transactions.

        Args:
            private_key_path (str, optional): Path to the private key file.
                If provided, will load the key for transaction signing.

        """
        if private_key_path:
            try:
                with open(private_key_path, "rb") as f:
                    key_data = f.read()
                    self.private_key = load_pem_private_key(key_data, password=None, backend=default_backend())
            except Exception as e:
                raise Exception(f"Failed to load private key: {e}")

    def send_request(self, command, payload, verbose=False):
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
        url = f"{self.node_address}{command}"
        headers = {"Content-Type": "application/json"}

        if verbose:
            print(f"Request URL: {url}")
            print(f"Request payload: {json.dumps(payload, indent=2)}")

        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()

            if verbose:
                print(f"Response: {json.dumps(result, indent=2)}")

            return result
        except Exception as e:
            raise Exception(f"API request failed: {e}")

    def create_account_identifier(self, principal, subaccount=None, verbose=False):
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
        account = {"address": principal}

        if subaccount:
            account["metadata"] = {"sub_account": subaccount}

        if verbose:
            print(f"Created account identifier: {json.dumps(account, indent=2)}")

        return account

    def list_networks(self, verbose=False):
        """
        Get a list of available networks.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            list: List of available networks.

        """
        payload = {}
        return self.send_request("/network/list", payload, verbose)["network_identifiers"]

    def get_status(self, verbose=False):
        """
        Get the current status of the network.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Network status information.

        """
        payload = {"network_identifier": self.network}
        return self.send_request("/network/status", payload, verbose)

    def get_options(self, verbose=False):
        """
        Get the options supported by the network.

        Args:
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Network options information.

        """
        payload = {"network_identifier": self.network}
        return self.send_request("/network/options", payload, verbose)

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

        # If neither specified, get latest block
        if not block_identifier:
            # Empty block identifier gets the latest block
            pass

        payload = {"network_identifier": self.network, "block_identifier": block_identifier}

        return self.send_request("/block", payload, verbose)

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
        if not principal:
            raise ValueError("Principal ID is required")

        account_identifier = self.create_account_identifier(principal=principal, subaccount=subaccount, verbose=verbose)

        payload = {"network_identifier": self.network, "account_identifier": account_identifier}

        return self.send_request("/account/balance", payload, verbose)

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
            "network_identifier": self.network,
            "block_identifier": {"index": block_index},
            "transaction_identifier": {"hash": transaction_hash},
        }

        return self.send_request("/block/transaction", payload, verbose)

    def search_transactions(self, principal=None, min_block=None, max_block=None, limit=None, verbose=False):
        """
        Search for transactions related to a principal.

        Args:
            principal (str, optional): The principal identifier. Defaults to None.
            min_block (int, optional): The minimum block index to search from. Defaults to None.
            max_block (int, optional): The maximum block index to search up to. Defaults to None (latest block).
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: The search results.

        """
        payload = {
            "network_identifier": self.network,
        }

        # Add account if specified
        if principal:
            payload["account_identifier"] = self.create_account_identifier(principal=principal, verbose=verbose)

        # Add block range if specified
        if min_block is not None or max_block is not None:
            payload["blockchain_identifier"] = {}

            if min_block is not None:
                payload["blockchain_identifier"]["min_block"] = {"index": min_block}

            if max_block is not None:
                payload["blockchain_identifier"]["max_block"] = {"index": max_block}

        # Add limit if specified
        if limit is not None:
            payload["limit"] = limit

        return self.send_request("/search/transactions", payload, verbose)

    def prepare_transfer_operations(
        self, from_principal, from_subaccount=None, to_principal=None, to_subaccount=None, amount=0, fee=0
    ):
        """
        Prepare operations for a transfer transaction.

        Args:
            from_principal (str): Sender's principal identifier
            from_subaccount (str, optional): Sender's subaccount in hex format
            to_principal (str, optional): Recipient's principal identifier
            to_subaccount (str, optional): Recipient's subaccount in hex format
            amount (int): Amount to transfer
            fee (int): Fee to pay

        Returns:
            list: Operations to submit

        """
        operations = []

        # Add the fee operation (index 0)
        if fee > 0:
            operations.append(
                {
                    "operation_identifier": {"index": 0},
                    "type": "FEE",
                    "account": self.create_account_identifier(principal=from_principal, subaccount=from_subaccount),
                    "amount": {
                        "value": str(-fee),  # Negative for outgoing
                        "currency": {"symbol": "ICP", "decimals": 8},
                    },
                }
            )

        # Add sender's debit operation (index 1 or 0 if no fee)
        operations.append(
            {
                "operation_identifier": {"index": 1 if fee > 0 else 0},
                "type": "TRANSACTION",
                "account": self.create_account_identifier(principal=from_principal, subaccount=from_subaccount),
                "amount": {
                    "value": str(-amount),  # Negative for outgoing
                    "currency": {"symbol": "ICP", "decimals": 8},
                },
            }
        )

        # Add recipient's credit operation (index 2 or 1 if no fee)
        if to_principal:
            operations.append(
                {
                    "operation_identifier": {"index": 2 if fee > 0 else 1},
                    "type": "TRANSACTION",
                    "account": self.create_account_identifier(principal=to_principal, subaccount=to_subaccount),
                    "amount": {
                        "value": str(amount),  # Positive for incoming
                        "currency": {"symbol": "ICP", "decimals": 8},
                    },
                }
            )

        return operations

    def sign_payload(self, payload_bytes):
        """
        Sign a payload using the private key.

        Args:
            payload_bytes (bytes): The payload to sign

        Returns:
            str: The signature in hex format

        """
        if not self.private_key:
            raise Exception("No private key configured. Call setup_keys() first.")

        # Different signing methods depending on key type
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            # For ECDSA keys
            signature = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA512()))
            return signature.hex()
        else:
            raise Exception("Unsupported private key type")

    @staticmethod
    def derive_key_info(private_key_path, verbose=False):
        """
        Derive public key and principal ID information from a private key file.

        This static method allows you to extract key information without
        initializing a full client. It returns both the hex-encoded public key
        and the derived principal ID according to Internet Computer standards.

        Args:
            private_key_path (str): Path to the private key file
            verbose (bool, optional): Whether to print verbose output. Defaults to False.

        Returns:
            dict: Dictionary containing public key information and principal ID

        """
        try:
            # Load the private key
            with open(private_key_path, "rb") as f:
                key_data = f.read()
                private_key = load_pem_private_key(key_data, password=None, backend=default_backend())

            # Get the public key in compressed format
            public_key = private_key.public_key().public_bytes(
                encoding=Encoding.X962, format=PublicFormat.CompressedPoint
            )

            # Hash the public key using SHA-224 to derive the principal
            key_hash = hashlib.sha224(public_key).digest()

            # Calculate CRC32 checksum
            crc = RosettaClient.crc32_ieee(key_hash)
            crc_bytes = crc.to_bytes(4, byteorder="big")

            # Combine CRC and key hash to create principal bytes
            principal_bytes = crc_bytes + key_hash

            # Format the principal using the Internet Computer representation
            principal_id = RosettaClient.format_principal_id(principal_bytes)

            result = {
                "public_key": {
                    "hex_bytes": public_key.hex(),
                    "curve_type": "secp256k1" if isinstance(private_key, ec.EllipticCurvePrivateKey) else "unknown",
                },
                "principal_id": principal_id,
            }

            if verbose:
                print(f"Derived key information: {json.dumps(result, indent=2)}")

            return result
        except Exception as e:
            raise Exception(f"Failed to derive key information: {e}")

    @staticmethod
    def crc32_ieee(data):
        """
        Calculate CRC-32 checksum.

        Args:
            data (bytes): Data to calculate checksum for

        Returns:
            int: CRC-32 checksum

        """
        # Calculate CRC-32 and convert to unsigned 32-bit int
        return zlib.crc32(data) & 0xFFFFFFFF

    @staticmethod
    def format_principal_id(bytes_with_crc):
        """
        Format principal bytes to the canonical text representation.
        Official Internet Computer principal ID format.

        Args:
            bytes_with_crc (bytes): Principal bytes with CRC-32 prepended

        Returns:
            str: Formatted principal ID

        """
        # Base32 encode the bytes and convert to string
        encoded = base64.b32encode(bytes_with_crc).decode("ascii").lower()

        # Remove padding characters
        encoded = encoded.rstrip("=")

        # Chunk the string and join with dashes
        chunks = [encoded[i : i + 5] for i in range(0, len(encoded), 5)]
        return "-".join(chunks)

    def transfer(
        self,
        from_principal,
        to_principal,
        amount,
        fee,
        private_key_path=None,
        signature_type="ecdsa",
        from_subaccount=None,
        to_subaccount=None,
        memo=None,
        verbose=False,
    ):
        """
        Transfer tokens between principals.

        Args:
            from_principal (str): Sender's principal identifier
            to_principal (str): Recipient's principal identifier
            amount (int): Amount to transfer
            fee (int): Fee to pay for the transaction
            private_key_path (str, optional): Path to sender's private key
            signature_type (str, optional): Type of signature to use
            from_subaccount (str, optional): Sender's subaccount
            to_subaccount (str, optional): Recipient's subaccount
            memo (list, optional): Optional memo field
            verbose (bool, optional): Whether to print verbose output

        Returns:
            dict: The response from the API

        """
        # Set up the private key
        if private_key_path:
            self.setup_keys(private_key_path)

        if not self.private_key:
            raise Exception("Private key is required for transfers. " + "Please provide a private_key_path.")

        # Prepare operations
        operations = self.prepare_transfer_operations(
            from_principal, from_subaccount, to_principal, to_subaccount, amount, fee
        )

        # Build the transaction
        transaction = {"operations": operations}

        # Add memo if provided
        if memo:
            transaction["metadata"] = {"memo": memo}

        # Construct the signing payload
        payload = {
            "network_identifier": self.network,
            "transaction": transaction,
            "metadata": {"signature_type": signature_type},
        }

        # Submit to get the unsigned blob
        if verbose:
            print("Requesting unsigned transaction...")

        construct_response = self.send_request("/construction/payloads", payload, verbose)

        unsigned_tx = construct_response.get("unsigned_transaction")
        signing_payload = construct_response.get("payloads")[0]

        # Sign the transaction
        if verbose:
            print("Signing transaction...")

        bytes_to_sign = bytes.fromhex(signing_payload["hex_bytes"])
        signature_hex = self.sign_payload(bytes_to_sign)

        # Combine the signature with the unsigned transaction
        combine_payload = {
            "network_identifier": self.network,
            "unsigned_transaction": unsigned_tx,
            "signatures": [
                {
                    "signing_payload": signing_payload,
                    "public_key": {
                        "hex_bytes": self.private_key.public_key()
                        .public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
                        .hex(),
                        "curve_type": "secp256k1",
                    },
                    "signature_type": signature_type,
                    "hex_bytes": signature_hex,
                }
            ],
        }

        # Get the signed transaction
        if verbose:
            print("Combining transaction...")

        combine_response = self.send_request("/construction/combine", combine_payload, verbose)

        signed_tx = combine_response.get("signed_transaction")

        # Submit the transaction
        if verbose:
            print("Submitting transaction...")

        submit_payload = {"network_identifier": self.network, "signed_transaction": signed_tx}

        return self.send_request("/construction/submit", submit_payload, verbose)
