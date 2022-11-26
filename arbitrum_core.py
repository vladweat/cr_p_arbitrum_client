import config

import time
from time import sleep
import random
import config
import datetime
import requests
import eth_abi

from loguru import logger
from decimal import Decimal
from pycoingecko import CoinGeckoAPI
from web3 import Web3, HTTPProvider


class ArbitrumCore:
    def __init__(self, run: str, network: str) -> None:
        # FOR PROD
        if (
            run
            == "Special for https://t.me/importweb3, creator - https://t.me/vladweat"
        ):
            logger.info(f"{run}")
            pass
        else:
            logger.error(f"Fatal error in script. FO!")
            raise SystemExit(1)

        self._web3 = self._set_web3_rpc(network)
        self._wallets_dict = self.__create_wallets_dict()
        self._len_wallets_dict = self.__get_len_wallets_dict()

    def _set_web3_rpc(self, network: str) -> Web3:
        """RPC setter

        Args:
            network (str): string with name of network

        Raises:
            SystemExit: if wrong network string input

        Returns:
            Web3: Web3 class
        """
        from web3.middleware import geth_poa_middleware

        if network == "arbitrum":
            return Web3(HTTPProvider(config.ARBITRUM_RPC))
        elif network == "mainnet":
            return Web3(HTTPProvider(config.MAINNET_RPC))
        elif network == "optimism":
            return Web3(HTTPProvider(config.OPTIMISM_RPC))
        else:
            logger.error(f"Wrong network RPC. Change it!")
            raise SystemExit(1)

    def _change_network_rpc(self, network: str) -> None:
        """Change network rpc by string

        Args:
            network (str): string with name of network
        """
        self._web3 = self._set_web3_rpc(network)

    def _check_connection(self) -> bool:
        """Check connection to RPC URL

        Returns:
            bool: connection status
        """
        try:
            return self._web3.isConnected()
        except Exception as e:
            logger.error(e)

    def _get_private_keys(self) -> list:
        """Return list of private keys from wallets.txt

        Returns:
            list: keys
        """
        try:
            with open("private_keys.txt", "r") as file:
                keys = file.read().splitlines()

            return keys

        except Exception as e:
            logger.error(e)

    def _check_private_keys(self) -> None:
        """Checking private keys for validity

        Raises:
            SystemExit: if 'Non-hexadecimal digit found' raised
        """
        if None in self._wallets_dict.values():
            logger.error(f"Fatal error in script. Change keys above!")
            raise SystemExit(1)
        else:
            logger.success(f"Private key verification passed!")

    def _get_address(self, private_key: str = None) -> str:
        """Return address from _wallets_dict[private_key]

        Args:
            private_key (str, optional): private key. Defaults to None.

        Returns:
            str: address from _wallets_dict[private_key]
        """
        try:
            address = self._wallets_dict.get(private_key)
            return address
        except Exception as e:
            logger.error(e)

    def _get_balance(self, private_key: str = None) -> float:
        """Get balance of address generated from _get_address(private_key)

        Args:
            private_key (str, optional): private key. Defaults to None.

        Returns:
            float: address balance
        """
        try:
            address = self._get_address(private_key)
            # balance = self._convert_from_ether_format(
            #     self._web3.eth.get_balance(address)
            # )
            balance = self._web3.eth.get_balance(address)
            return balance
        except Exception as e:
            logger.error(e)

    def _get_nonce(self, private_key: str) -> int:
        """Return nonce of address from private_key

        Args:
            private_key (str): private key

        Returns:
            int: nonce
        """
        try:
            address = self.__get_address(private_key)
            nonce = self._web3.eth.get_transaction_count(address)
            return nonce
        except Exception as e:
            logger.error(e)

    def _convert_from_ether_format(self, num: int = None) -> float:
        """Convert Wei to Ether format
        100000000000000000000 -> 100

        Args:
            num (integer): wei format integer

        Returns:
            float: _description_
        """
        try:
            ether_format = self._web3.fromWei(num, "ether")
            return ether_format
        except Exception as e:
            logger.error(e)

    def _convert_to_ether_format(self, num: float = None) -> int:
        """Convert Ether to Wei format
        100 -> 100000000000000000000
        Args:
            num (float): ether format integer

        Returns:
            int: _description_
        """
        try:
            wei_format = self._web3.toWei(Decimal(num), "ether")
            return wei_format
        except Exception as e:
            logger.error(e)

    def _convert_from_mwei_format(self, num: int = None) -> float:
        """Convert Wei to Mwei format
        1000000 -> 1
        Args:
            num (integer): wei format integer

        Returns:
            float: _description_
        """
        try:
            ether_format = self._web3.fromWei(num, "mwei")
            return ether_format
        except Exception as e:
            logger.error(e)

    def _convert_to_mwei_format(self, num: float = None) -> int:
        """Convert Mwei to Wei format
        1 -> 1000000
        Args:
            num (float): ether format integer

        Returns:
            int: _description_
        """
        try:
            wei_format = self._web3.toWei(Decimal(num), "mwei")
            return wei_format
        except Exception as e:
            logger.error(e)

    def _get_checksum_address(self, address: str) -> str:
        """Return toChecksumAddress(address)

        Args:
            address (str): address

        Returns:
            str: toChecksumAddress(address)
        """
        try:
            checksum_address = self._web3.toChecksumAddress(address)
            return checksum_address
        except Exception as e:
            logger.error(e)

    def _sign_transaction(self, transaction, private_key: str) -> dict:
        """Wrapper for web.eth.account.sign_transaction

        Args:
            transaction (_type_): transaction.method().buildTransaction()
            private_key (str): private key

        Returns:
            signed_tx: web3.eth.account.sign_transaction()
        """
        try:
            signed_tx = self._web3.eth.account.sign_transaction(
                transaction, private_key
            )
            return signed_tx
        except Exception as e:
            logger.error(e)

    def _send_raw_transaction(self, sign_txn: dict) -> str:
        """Wrapper for web3.eth.send_raw_transaction

        Args:
            sign_txn (_type_): sign_txn

        Returns:
            raw_tx_hash: raw_tx_hash
        """
        try:
            raw_tx_hash = self._web3.eth.send_raw_transaction(sign_txn.rawTransaction)
            return raw_tx_hash
        except Exception as e:
            logger.error(e)

    def _get_tx_hash(self, raw_tx_hash: str) -> str:
        """Wrapper for web3.toHex

        Args:
            raw_tx_hash (_type_): raw_tx_hash

        Returns:
            tx_hash: tx_hash
        """
        try:
            tx_hash = self._web3.toHex(raw_tx_hash)
            return tx_hash
        except Exception as e:
            logger.error(e)

    def __create_wallets_dict(self) -> dict:
        """Created dict with key:address args

        Returns:
            dict: dict{ private_key: 'address' }
        """
        try:
            private_keys = self._get_private_keys()
            wallets_dict = {}

            for key in private_keys:
                wallets_dict[key] = self.__get_address(key)

            return wallets_dict
        except Exception as e:
            logger.error(e)

    def __get_len_wallets_dict(self) -> int:
        """Return length of self._wallets_dict

        Returns:
            int: len of self._wallets_dict
        """
        return len(self._wallets_dict)

    def __get_address(self, private_key: str = None) -> str:
        """Return address generated from private_key

        Args:
            private_key (str, optional): private key. Defaults to None.

        Returns:
            str: address generated with web3.eth.account.from_key
        """
        if type(private_key) == str:
            try:
                account = self._web3.eth.account.from_key(private_key)
                return account.address

            except Exception as e:
                logger.error(f'{e}: Change key "{private_key}"')
        else:
            logger.error(
                f"Сan't get address from private key. Private key format is {type(private_key)}, must be <class 'str'>!"
            )

    def _wait_for_transaction_receipt(self, tx_hash) -> bool:
        """Wrapper for web3.eth.waitForTransactionReceipt()

        Args:
            tx_hash (str): hash from scan

        Returns:
            bool: bool
        """
        while True:
            try:
                tx_status = self._web3.eth.waitForTransactionReceipt(tx_hash).status
                if tx_status == 1:
                    logger.success(f"Tx {tx_hash} CONFIRMED")
                    return True
                else:
                    sleep(3)
            except Exception as e:
                logger.error(e)

    def _is_encodable(self, value, value_name, value_type) -> str:
        _value = value
        _value_name = str(value_name)
        _type = str(value_type)
        _is_encodable_str = (
            f"{_value_name} is {_type}? {self._web3.is_encodable(_type, _value)}"
        )
        return _is_encodable_str

    def _add_random_delay(self, min, max) -> bool:
        """Add random delay in [min, max]

        Args:
            min (int): min sec
            max (int): max sec

        Returns:
            bool: bool
        """
        time.sleep(random.randint(min, max))
        return True

    def _get_chain_id(self) -> int:
        """Wrapper for web3.eth.chain_id

        Returns:
            int: chain id
        """
        return self._web3.eth.chain_id

    def _get_gas_price(self) -> int:
        """Wrapper for web3.eth.gas_price

        Returns:
            int: gas price
        """
        return self._web3.eth.gas_price

    def _get_gas_limit(self, from_address: str, to_address: str, value: int) -> int:
        """Wrapper for web3.eth.estimate_gas

        Args:
            from_address (str): transaction.from
            to_address (str): transaction.to
            value (int): transaction.value

        Returns:
            int: gas limit
        """
        gas_limit = self._web3.eth.estimate_gas(
            {"to": to_address, "from": from_address, "value": value}
        )
        return gas_limit

    def _build_tx_param(
        self, from_private_key: str, to_address: str, value: int
    ) -> dict:
        """Build transaction parametrs

        Args:
            from_private_key (str): private key
            to_address (str): transaction.to
            value (int): transaction.value

        Returns:
            dict: transaction_param
        """
        address = self._get_checksum_address(self._get_address(from_private_key))
        _to_address = self._get_checksum_address(to_address)

        estimate = self._web3.eth.estimate_gas(
            {"to": _to_address, "from": address, "value": value}
        )
        gas_limit = estimate

        transaction_param = {
            "chainId": self._get_chain_id(),
            "from": address,
            "nonce": self._get_nonce(from_private_key),
            "to": _to_address,
            "value": value,
            "gas": gas_limit,
            "maxPriorityFeePerGas": self._web3.toWei(5, "gwei"),
            "maxFeePerGas": self._web3.toWei(10, "gwei"),
            # "gasPrice": self._get_gas_price(),
            "type": "0x2",
        }

        return transaction_param

    def _build_contract_tx_param(self, from_private_key: str, value: int) -> dict:
        """Build transaction parametrs to contract

        Args:
            from_private_key (str): private key
            value (int): transaction.value

        Returns:
            dict: transaction_param
        """
        address = self._get_checksum_address(self._get_address(from_private_key))

        transaction_param = {
            "chainId": self._get_chain_id(),
            "from": address,
            "nonce": self._get_nonce(from_private_key),
            "value": value,
            "type": "0x2",
            # "gasPrice": self._get_gas_price(),
        }

        return transaction_param

    def _sign_send_get_tx_hash(self, transaction: dict, private_key: str) -> str:
        """Wrapper for sign_transaction / send_raw_transaction / get_tx_hash

        Args:
            transaction (dict): transaction_param
            private_key (str): private_key

        Returns:
            str: transaction hash
        """
        signed_transaction = self._sign_transaction(transaction, private_key)
        raw_tx_hash = self._send_raw_transaction((signed_transaction))
        tx_hash = self._get_tx_hash(raw_tx_hash)
        return tx_hash

    def _get_token_price(self, coingecko_token_id: str) -> float:
        """Return USD value of coingecko_token_id

        Args:
            coingecko_token_id (str): token id from https://www.coingecko.com/

        Returns:
            float: USD value of token
        """
        try:
            cg = CoinGeckoAPI()
            token_price_req = cg.get_price(ids=coingecko_token_id, vs_currencies="usd")
            token_price = float(token_price_req[f"{coingecko_token_id}"]["usd"])
            return token_price

        except Exception as e:
            logger.error(e)

    def _get_transaction_receipt(self, tx_hash: str) -> dict:
        """Wrapper for web3.eth.get_transaction()

        Args:
            tx_hash (str): transaction hash

        Returns:
            dict: transaction receipt
        """
        transaction = self._web3.eth.get_transaction(tx_hash)
        return transaction

    def _get_fee_value(self, tx_hash: str) -> int:
        """Get fee value of transaction

        Args:
            tx_hash (str): transaction hash

        Returns:
            int: gas value
        """
        transaction = self._get_transaction_receipt(tx_hash)
        gas_limit = transaction["gas"]
        gas_price = transaction["gasPrice"]
        fee_value = gas_limit * self._convert_from_ether_format(gas_price)
        return fee_value

    def _get_fee_cost(self, tx_hash: str) -> float:
        """Geet fee cost from fee value

        Args:
            tx_hash (str): transaction hash

        Returns:
            float: fee in usdc
        """
        fee_value = self._get_fee_value(tx_hash)
        fee_cost = self._get_token_price("ethereum") * float(fee_value)
        return fee_cost
