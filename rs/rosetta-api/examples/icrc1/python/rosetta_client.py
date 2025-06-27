import base64  # For base32 encoding
import hashlib
import json
import time
import zlib  # For CRC32 calculation

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
        token_override: Token information override
        token_info: Discovered token information (symbol and decimals)

    """

    def __init__(self, node_address, canister_id, verbose):
        """
        Initialize the Rosetta client.

        Args:
            node_address (str): The URL of the Rosetta API endpoint.
            canister_id (str): The ICRC-1 canister identifier.
            verbose (bool): Whether to print verbose output.

        """
        self.node_address = node_address
        self.canister_id = canister_id
        self.private_key = None
        self.token_override = None

        # Get network information to use in subsequent requests
        network_list = self.list_networks(verbose=verbose)
        if not network_list:
            raise Exception("Could not determine network information")

        # Try to find the network matching our canister ID
        self.network = None
        for network in network_list:
            if network["network"] == canister_id:
                self.network = {"blockchain": network["blockchain"], "network": network["network"]}
                break

        # If no matching network found, default to the first one
        if self.network is None:
            self.network = {"blockchain": network_list[0]["blockchain"], "network": network_list[0]["network"]}
            if verbose:
                print(
                    f"Warning: Could not find network for canister ID {canister_id}. Using {self.network['network']} instead."
                )

        # Automatically discover token information
        self.token_info = self.discover_token_information(verbose=verbose)

    def setup_keys(self, private_key_path):
        """
        Set up the cryptographic keys for signing transactions.

        Args:
            private_key_path (str): Path to the private key file.

        """
        try:
            with open(private_key_path, "rb") as f:
                key_data = f.read()
                self.private_key = load_pem_private_key(key_data, password=None, backend=default_backend())
        except Exception as e:
            raise Exception(f"Failed to load private key: {e}")

    def send_request(self, command, payload, verbose):
        """
        Send a request to the Rosetta API.

        Args:
            command (str): The API command/endpoint to call.
            payload (dict): The request payload.
            verbose (bool): Whether to print verbose output.

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

            # Try to get the response as JSON
            try:
                result = response.json()
                if verbose:
                    print(f"Response: {json.dumps(result, indent=2)}")
            except Exception:
                # If not JSON, just get the text
                if verbose:
                    print(f"Response (non-JSON): {response.text}")
                result = {"error": "Unable to parse response as JSON", "raw_response": response.text}

            # Check if we have a success response
            response.raise_for_status()

            return result
        except requests.exceptions.HTTPError as e:
            # Get detailed error message if available
            error_message = str(e)
            try:
                if hasattr(response, "text") and response.text:
                    if verbose:
                        print(f"Error response: {response.text}")
                    # Try to get JSON error details
                    try:
                        error_details = response.json()
                        error_message = (
                            f"API request failed with status {response.status_code}: {json.dumps(error_details)}"
                        )
                    except json.JSONDecodeError:
                        # If not JSON, use the raw text
                        error_message = f"API request failed with status {response.status_code}: {response.text}"
            except Exception:
                pass

            raise Exception(error_message)
        except Exception as e:
            # Handle other exceptions
            raise Exception(f"API request failed: {e}")

    def create_account_identifier(self, principal, subaccount, verbose):
        """
        Create the account identifier object from principal and subaccount.

        In ICRC-1, accounts are identified by a principal ID and an optional subaccount.

        Args:
            principal (str): Principal identifier
            subaccount (str): Subaccount in hex format
            verbose (bool): Whether to print verbose output

        Returns:
            dict: Account identifier object with address and optional sub_account

        """
        account = {"address": principal}

        if subaccount:
            account["sub_account"] = {"address": subaccount}

        if verbose:
            print(f"Created account identifier: {json.dumps(account, indent=2)}")

        return account

    def list_networks(self, verbose):
        """
        Get a list of available networks.

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            list: List of available networks.

        """
        payload = {}
        return self.send_request("/network/list", payload, verbose)["network_identifiers"]

    def get_status(self, verbose):
        """
        Get the current status of the network.

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Network status information.

        """
        payload = {"network_identifier": self.network}
        return self.send_request("/network/status", payload, verbose)

    def get_options(self, verbose):
        """
        Get the options supported by the network.

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Network options information.

        """
        payload = {"network_identifier": self.network}
        return self.send_request("/network/options", payload, verbose)

    def get_block(self, block_index, block_hash, verbose):
        """
        Get a specific block by index or hash.

        Args:
            block_index (int): The block index/height.
            block_hash (str): The block hash.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: The block information.

        """
        block_identifier = {}

        if block_index is not None:
            block_identifier["index"] = block_index

        if block_hash is not None:
            block_identifier["hash"] = block_hash

        # If neither specified, get latest block
        # Empty block identifier gets the latest block - leave as empty dict

        payload = {"network_identifier": self.network, "block_identifier": block_identifier}

        return self.send_request("/block", payload, verbose)

    def get_balance(self, principal, subaccount, verbose):
        """
        Get the balance of a principal and optional subaccount.

        Args:
            principal (str): The principal identifier.
            subaccount (str): The subaccount in hex format.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: The balance information.

        """
        if not principal:
            raise ValueError("Principal ID is required")

        account_identifier = self.create_account_identifier(principal=principal, subaccount=subaccount, verbose=verbose)

        payload = {"network_identifier": self.network, "account_identifier": account_identifier}

        balance_response = self.send_request("/account/balance", payload, verbose)

        # If response doesn't include currency information, add our discovered token info
        if "balances" in balance_response and balance_response["balances"]:
            for balance in balance_response["balances"]:
                if "currency" not in balance:
                    # Use token_override if set, otherwise use discovered token_info
                    if self.token_override:
                        balance["currency"] = self.token_override
                    else:
                        balance["currency"] = self.token_info

        return balance_response

    def get_aggregated_balance(self, principal, verbose=False):
        """
        Get the aggregated balance of all subaccounts for a principal.
        
        This method returns the sum of balances across all subaccounts 
        of the specified principal.

        Args:
            principal (str): The principal identifier.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: The aggregated balance information.

        """
        if not principal:
            raise ValueError("Principal ID is required")

        # Create account identifier without subaccount (principal only)
        account_identifier = self.create_account_identifier(principal=principal, subaccount=None, verbose=verbose)

        # Add the aggregate_all_subaccounts flag to metadata
        payload = {
            "network_identifier": self.network, 
            "account_identifier": account_identifier,
            "metadata": {
                "aggregate_all_subaccounts": True
            }
        }

        balance_response = self.send_request("/account/balance", payload, verbose)

        # If response doesn't include currency information, add our discovered token info
        if "balances" in balance_response and balance_response["balances"]:
            for balance in balance_response["balances"]:
                if "currency" not in balance:
                    # Use token_override if set, otherwise use discovered token_info
                    if self.token_override:
                        balance["currency"] = self.token_override
                    else:
                        balance["currency"] = self.token_info

        return balance_response

    def get_transaction(self, block_index, transaction_hash, verbose):
        """
        Fetch a specific transaction from a block.

        Args:
            block_index (int): The block index.
            transaction_hash (str): The transaction hash.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: The transaction information.

        """
        payload = {
            "network_identifier": self.network,
            "block_identifier": {"index": block_index},
            "transaction_identifier": {"hash": transaction_hash},
        }

        return self.send_request("/block/transaction", payload, verbose)

    def search_transactions(self, principal, min_block, max_block, limit, verbose):
        """
        Search for transactions related to a principal.

        Args:
            principal (str): The principal identifier.
            min_block (int): The minimum block index to search from.
            max_block (int): The maximum block index to search up to.
            limit (int): Maximum number of transactions to return.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: The search results.

        """
        payload = {
            "network_identifier": self.network,
        }

        # Add account if specified
        if principal:
            payload["account_identifier"] = self.create_account_identifier(
                principal=principal, verbose=verbose, subaccount=None
            )

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

    def prepare_transfer_operations(self, from_principal, from_subaccount, to_principal, to_subaccount, amount, fee):
        """
        Prepare operations for a transfer transaction.

        Args:
            from_principal (str): Sender's principal identifier
            from_subaccount (str): Sender's subaccount in hex format
            to_principal (str): Recipient's principal identifier
            to_subaccount (str): Recipient's subaccount in hex format
            amount (int): Amount to transfer
            fee (int): Fee to pay

        Returns:
            list: Operations to submit

        """
        operations = []

        # Get token and operation information from the network options
        # This ensures we're using the correct token symbol and decimals
        # as well as the proper operation types and order
        allowed_operations = []  # Initialize with default empty list
        try:
            network_options = self.get_options(verbose=False)
            currency_info = {}

            # Extract allowed operations (including their order)
            if network_options and "allow" in network_options:
                if "operation_types" in network_options["allow"]:
                    allowed_operations = network_options["allow"]["operation_types"]

                if "currencies" in network_options["allow"]:
                    # Get the first currency as default (usually there's only one for ICRC-1 ledgers)
                    if network_options["allow"]["currencies"]:
                        currency_info = network_options["allow"]["currencies"][0]
        except Exception:
            # If we couldn't get network options, we'll use default values
            pass

        # Decide which token info to use, in order of priority:
        # 1. Explicit token override (if set by user)
        # 2. Network options (from API)
        # 3. Discovered token_info from initialization
        if self.token_override:
            symbol = self.token_override["symbol"]
            decimals = self.token_override["decimals"]
        elif currency_info:
            symbol = currency_info.get("symbol", self.token_info["symbol"])
            decimals = currency_info.get("decimals", self.token_info["decimals"])
        else:
            # Use our discovered token info
            symbol = self.token_info["symbol"]
            decimals = self.token_info["decimals"]

        # Check if we should follow a specific order of operations
        # If we have allowed_operations info, use that order
        transfer_type = "TRANSFER"  # Default
        fee_type = "FEE"  # Default

        if "TRANSFER" in allowed_operations:
            transfer_type = "TRANSFER"
        elif "TRANSACTION" in allowed_operations:
            transfer_type = "TRANSACTION"

        # Create operations based on our best understanding of the API requirements
        operation_index = 0

        # If the client expects recipient operation first (based on allowed_operations)
        # Some ICRC-1 Rosetta APIs expect recipient credit first, then sender debit
        if to_principal:
            operations.append(
                {
                    "operation_identifier": {"index": operation_index},
                    "type": transfer_type,
                    "account": self.create_account_identifier(
                        principal=to_principal, subaccount=to_subaccount, verbose=False
                    ),
                    "amount": {
                        "value": str(amount),  # Positive for incoming
                        "currency": {"symbol": symbol, "decimals": decimals},
                    },
                }
            )
            operation_index += 1

        # Then sender's debit operation
        operations.append(
            {
                "operation_identifier": {"index": operation_index},
                "type": transfer_type,
                "account": self.create_account_identifier(
                    principal=from_principal, subaccount=from_subaccount, verbose=False
                ),
                "amount": {
                    "value": str(-amount),  # Negative for outgoing
                    "currency": {"symbol": symbol, "decimals": decimals},
                },
            }
        )
        operation_index += 1

        # Then fee operation if applicable
        if fee > 0:
            operations.append(
                {
                    "operation_identifier": {"index": operation_index},
                    "type": fee_type,
                    "account": self.create_account_identifier(
                        principal=from_principal, subaccount=from_subaccount, verbose=False
                    ),
                    "amount": {
                        "value": str(-fee),  # Negative for outgoing
                        "currency": {"symbol": symbol, "decimals": decimals},
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
            # The Internet Computer expects signatures with a specific hashing algorithm
            # Try SHA-256 which is commonly used in IC
            try:
                # When the payload starts with b'ic-request', this is the format the IC expects
                from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

                # Use SHA-256 for hashing which is standard for IC
                der_signature = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

                # Decode the DER signature to get the raw r and s values
                r, s = decode_dss_signature(der_signature)

                # Convert to 32-byte values and concatenate
                r_bytes = r.to_bytes(32, byteorder="big")
                s_bytes = s.to_bytes(32, byteorder="big")
                raw_signature = r_bytes + s_bytes  # 64 bytes total

                return raw_signature.hex()
            except ImportError:
                raise Exception("Could not import decode_dss_signature. Please install cryptography package.")
        else:
            raise Exception("Unsupported private key type")

    @staticmethod
    def derive_key_info(private_key_path, verbose):
        """
        Derive public key and principal ID information from a private key file.

        This static method allows you to extract key information without
        initializing a full client. It returns both the hex-encoded public key
        and the derived principal ID according to Internet Computer standards.

        Args:
            private_key_path (str): Path to the private key file
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Dictionary containing public key information and principal ID

        """
        try:
            # Load the private key
            with open(private_key_path, "rb") as f:
                key_data = f.read()
                private_key = load_pem_private_key(key_data, password=None, backend=default_backend())

            # Get the compressed format for display and storage
            compressed_pub_key = private_key.public_key().public_bytes(
                encoding=Encoding.X962, format=PublicFormat.CompressedPoint
            )

            if verbose:
                print(f"Compressed public key: {compressed_pub_key.hex()}")

            # Get the uncompressed public key in SEC1 format
            # This matches what's used in the Rust IC code for Secp256k1 keys
            uncompressed_pub_key = private_key.public_key().public_bytes(
                encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
            )

            if verbose:
                print(f"Uncompressed public key (SEC1): {uncompressed_pub_key.hex()}")

            # Get the DER format (SubjectPublicKeyInfo)
            der_pub_key = private_key.public_key().public_bytes(
                encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
            )

            if verbose:
                print(f"DER public key: {der_pub_key.hex()}")

            # Hash using SHA-224
            # The Rust implementation in ic/rs/types/base_types/src/principal_id.rs uses
            # the DER-encoded public key for hashing
            hash_bytes = hashlib.sha224(der_pub_key).digest()

            # Append the self-authenticating tag (0x02)
            # The value 2 corresponds to PrincipalIdClass::SelfAuthenticating in Rust
            principal_bytes = hash_bytes + bytes([2])

            if verbose:
                print(f"Hash: {hash_bytes.hex()}")
                print(f"Principal bytes: {principal_bytes.hex()}")

            # Format as Internet Computer principal ID with CRC
            principal_id = RosettaClient.format_principal_id(principal_bytes)

            result = {
                "public_key": {
                    "hex_bytes": compressed_pub_key.hex(),
                    "curve_type": "secp256k1" if isinstance(private_key, ec.EllipticCurvePrivateKey) else "unknown",
                },
                "principal_id": principal_id,
            }

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
    def format_principal_id(principal_bytes):
        """
        Format principal bytes to the canonical text representation.
        Official Internet Computer principal ID format.

        The format includes a CRC32 checksum, followed by base32 encoding
        without padding, groups the characters in sets of 5, and
        separates them with hyphens.

        Args:
            principal_bytes (bytes): Principal bytes with class tag (29 bytes)

        Returns:
            str: Formatted principal ID

        """
        # According to the Internet Computer Wiki, principal IDs include a CRC-32 checksum
        # Calculate CRC32 of the principal bytes
        crc = RosettaClient.crc32_ieee(principal_bytes)

        # Convert CRC to bytes in big-endian format
        crc_bytes = crc.to_bytes(4, byteorder="big")

        # Prepend CRC to the principal bytes
        bytes_with_crc = crc_bytes + principal_bytes

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
        private_key_path,
        signature_type,
        from_subaccount,
        to_subaccount,
        memo,
        verbose,
    ):
        """
        Transfer tokens between principals.

        Args:
            from_principal (str): Sender's principal identifier
            to_principal (str): Recipient's principal identifier
            amount (int): Amount to transfer
            fee (int): Fee to pay for the transaction
            private_key_path (str): Path to sender's private key
            signature_type (str): Type of signature to use
            from_subaccount (str): Sender's subaccount
            to_subaccount (str): Recipient's subaccount
            memo (list): Optional memo field
            verbose (bool): Whether to print verbose output

        Returns:
            dict: The response from the API

        """
        # Set up the private key
        if private_key_path:
            self.setup_keys(private_key_path)

        if not self.private_key:
            raise Exception("Private key is required for transfers. " + "Please provide a private_key_path.")

        # Get public key information
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=Encoding.X962, format=PublicFormat.CompressedPoint
        )
        public_key_hex = public_key_bytes.hex()

        # Prepare operations
        operations = self.prepare_transfer_operations(
            from_principal, from_subaccount, to_principal, to_subaccount, amount, fee
        )

        # Set transaction metadata
        metadata = {"signature_type": signature_type}

        # Add created_at_time in nanoseconds (required by some ICRC-1 Rosetta implementations)
        current_time_ns = int(time.time() * 1000000000)  # Convert to nanoseconds
        metadata["created_at_time"] = current_time_ns

        # Add memo if provided
        if memo:
            metadata["memo"] = memo

        # Construct the payload
        payload = {
            "network_identifier": self.network,
            "operations": operations,
            "metadata": metadata,
            "public_keys": [{"hex_bytes": public_key_hex, "curve_type": "secp256k1"}],
        }

        # Submit to get the unsigned blob
        if verbose:
            print("Requesting unsigned transaction...")

        construct_response = self.send_request("/construction/payloads", payload, verbose)

        unsigned_tx = construct_response.get("unsigned_transaction")
        signing_payloads = construct_response.get("payloads", [])

        # Sign the transaction
        if verbose:
            print("Signing transaction...")

        signatures = []
        for payload_info in signing_payloads:
            bytes_to_sign = bytes.fromhex(payload_info["hex_bytes"])
            signature_hex = self.sign_payload(bytes_to_sign)

            signatures.append(
                {
                    "signing_payload": payload_info,
                    "public_key": {
                        "hex_bytes": public_key_hex,
                        "curve_type": "secp256k1",
                    },
                    "signature_type": signature_type,
                    "hex_bytes": signature_hex,
                }
            )

        # Combine the signature with the unsigned transaction
        combine_payload = {
            "network_identifier": self.network,
            "unsigned_transaction": unsigned_tx,
            "signatures": signatures,
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

    def get_token_info_from_blocks(self, num_blocks, verbose):
        """
        Get token information (symbol and decimals) by examining recent blocks.

        This method fetches the last several blocks and extracts token information
        from any transactions found. This is useful when other methods of getting
        token info fail.

        Args:
            num_blocks (int): Number of recent blocks to check.
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Token information with symbol and decimals, or None if not found

        """
        if verbose:
            print(f"Fetching token info from the last {num_blocks} blocks...")

        # Try to get the current block height
        try:
            status = self.get_status(verbose=False)
            if not status or "current_block_identifier" not in status:
                if verbose:
                    print("Could not determine current block height")
                return None

            current_height = status["current_block_identifier"]["index"]
            if verbose:
                print(f"Current block height: {current_height}")

            # Scan recent blocks
            for i in range(num_blocks):
                block_index = max(0, current_height - i)
                if verbose:
                    print(f"Checking block {block_index}...")

                token_info = self._extract_token_info_from_block(block_index, verbose)
                if token_info:
                    return token_info

            if verbose:
                print(f"No token information found in the last {num_blocks} blocks")

        except Exception as e:
            if verbose:
                print(f"Error fetching token info from blocks: {e}")

        return None

    def _extract_token_info_from_block(self, block_index, verbose):
        """Helper method to extract token info from a specific block"""
        try:
            block_data = self.get_block(block_index=block_index, verbose=False)

            # Early return if no valid block data
            if not block_data or "block" not in block_data or "transactions" not in block_data["block"]:
                return None

            transactions = block_data["block"]["transactions"]

            # Look through all transactions
            for tx in transactions:
                if "operations" not in tx or not tx["operations"]:
                    continue

                # Look through operations
                for op in tx["operations"]:
                    if "amount" not in op or "currency" not in op["amount"]:
                        continue

                    currency = op["amount"]["currency"]
                    token_info = {"symbol": currency.get("symbol", "Unknown"), "decimals": currency.get("decimals", 8)}

                    if verbose:
                        print(f"Found token info in block {block_index}: {token_info}")

                    return token_info

        except Exception as e:
            if verbose:
                print(f"Error processing block {block_index}: {e}")

        return None

    def discover_token_information(self, verbose):
        """
        Discover token information by trying multiple methods in order of reliability.

        This method attempts to get token symbol and decimals by:
        1. Checking network options
        2. Checking transaction history in recent blocks

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Token information with symbol and decimals

        """
        # Default fallback values if nothing else works
        token_info = {"symbol": "ICRC1", "decimals": 8}

        # Method 1: Try network options
        token_info_from_options = self._get_token_info_from_options(verbose)
        if token_info_from_options:
            return token_info_from_options

        # Method 2: Try recent blocks
        token_info_from_blocks = self._get_token_info_from_blocks_internal(verbose)
        if token_info_from_blocks:
            return token_info_from_blocks

        if verbose:
            print(f"Using default token info: {token_info}")

        return token_info

    def _get_token_info_from_options(self, verbose):
        """
        Internal helper to get token info from network options

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Token information with symbol and decimals, or None if not found

        """
        try:
            options = self.get_options(verbose)
            if not options or "allow" not in options or "currencies" not in options["allow"]:
                return None

            currencies = options["allow"]["currencies"]
            if not currencies:
                return None

            currency = currencies[0]
            token_info = {"symbol": currency.get("symbol", "ICRC1"), "decimals": currency.get("decimals", 8)}

            if verbose:
                print(f"Got token info from network options: {token_info}")

            return token_info
        except Exception:
            return None

    def _get_token_info_from_blocks_internal(self, verbose):
        """
        Internal helper to get token info from recent blocks

        Args:
            verbose (bool): Whether to print verbose output.

        Returns:
            dict: Token information with symbol and decimals, or None if not found

        """
        try:
            # Use 5 blocks as a reasonable number to check
            block_info = self.get_token_info_from_blocks(num_blocks=5, verbose=verbose)
            if block_info:
                if verbose:
                    print(f"Got token info from recent blocks: {block_info}")
                return block_info
        except Exception:
            pass

        return None
