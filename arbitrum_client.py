import time
from time import sleep
import random
import config
import datetime
import requests
import eth_abi
import json

from loguru import logger
from arbitrum_core import ArbitrumCore


class ArbitrumClient:
    def __init__(self, core: ArbitrumCore) -> None:
        self.arbitrum_core = core
        self._arbiscan_api_key = config.ARBISCAN_API_KEY

    def _get_abi(self, network, contract: str) -> dict:

        if network == "arbitrum":
            API_KEY = self._arbiscan_api_key
            contract_url = f"https://api.arbiscan.io/api?module=contract&action=getabi&address={contract}&apikey={API_KEY}"

        elif network == "mainnet":
            API_KEY = config.MAINNET_API_KEY
            contract_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract}&apikey={API_KEY}"

        else:
            logger.error(f"Wrong network!")

        try:
            request = requests.get(contract_url)
            data = request.json()
            if data["status"] == "1":
                abi = data["result"]
                return abi
            else:
                logger.error(f'Failed request. Error: {data["result"]}')

        except Exception as e:
            logger.error(e)

    def _get_arb_function_by_signature(
        self, contract_address: str, signature: str
    ) -> object:
        """Return function from arbitrum contract

        Args:
            contract_address (str): contract address from arbiscan
            signature (str): MethodID from transaction Input Data

        Returns:
            object: function from "get_function_by_selector(signature)"
        """
        try:
            checksum_address = self.arbitrum_core._web3.toChecksumAddress(
                contract_address
            )
            abi = self._get_arbitrum_abi(contract_address)
            contract = self.arbitrum_core._web3.eth.contract(
                address=checksum_address, abi=abi
            )
            function = contract.get_function_by_selector(signature)
            return function

        except Exception as e:
            logger.error(f"Wrong address or abi. Error: {e}")

    def _get_function_by_signature(
        self, network: str, proxy_contract: str, contract: str, signature: str
    ) -> object:
        try:
            abi = self._get_abi(network, proxy_contract)

            contract_address = self.arbitrum_core._get_checksum_address(contract)

            contract = self.arbitrum_core._web3.eth.contract(
                address=contract_address, abi=abi
            )

            function = contract.get_function_by_selector(signature)
            return function

        except Exception as e:
            logger.error(f"Wrong address or abi. Error: {e}")

    def _get_deadline(self, expiry_seconds: int) -> int:
        return int(time.time()) + expiry_seconds

    def _int_to_decimal(self, qty, decimal) -> int:
        return int(qty * int("".join(["1"] + ["0"] * decimal)))

    def _randomise_value(self, value: float, persent: float = None) -> float:
        """Return random value in (value * (100 - percent)%, value * (100 + percent)%)

        Args:
            value (float): input value

        Returns:
            float: output random value
        """
        try:
            _percent = persent
            min_value = value - (value * (_percent / 100))
            max_value = value + (value * (_percent / 100))
            random_value = random.uniform(min_value, max_value)
            return random_value
        except Exception as e:
            logger.error(e)

    def _get_eth_price_arbitrum(self) -> float:
        """Return ETH price in USD from arbiscan

        Returns:
            float: ethusd_price
        """
        API_KEY = self._arbiscan_api_key
        try:
            arbiscan_contract_url = f"https://api.arbiscan.io/api?module=stats&action=ethprice&apikey={API_KEY}"
            request = requests.get(arbiscan_contract_url)
            data = request.json()

            if data["status"] == "1":
                response = data["result"]
                ethusd_price = response["ethusd"]
                return ethusd_price
            else:
                logger.error(f'Failed to get abi. Error: {data["result"]}')

        except Exception as e:
            logger.error(e)

    def _value_with_slippage(self, amount: float, slippage: float) -> int:
        """Return value with slippage

        Args:
            amount (float): input value
            slippage (float): slippage %

        Returns:
            int: value - (value with slippage)
        """
        try:
            slippage = slippage / 100
            min_amount = amount - (amount * slippage)
            return min_amount
        except Exception as e:
            logger.error(e)

    def bridge_mainnet_to_arb_one(self, private_key: str, eth_value: float) -> None:
        address = self.arbitrum_core._get_address(private_key)

        network = "mainnet"
        contract = "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f"
        proxy = "0x931E1770BEC7827841f3989bda43319adACD62db"
        signature = "0x439370b1"

        deposit_eth_function = self._get_function_by_signature(
            network, proxy, contract, signature
        )

        _eth_value = eth_value

        value = self.arbitrum_core._convert_to_ether_format(_eth_value)

        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, value)

        transaction = deposit_eth_function().buildTransaction(tx_param)

        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} bridge {eth_value} ETH from mainnet to arbitrum one. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )
        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)

    def bridge_mainnet_to_arb_nova(self, private_key: str, eth_value: float) -> None:
        address = self.arbitrum_core._get_address(private_key)

        network = "mainnet"
        contract = "0xc4448b71118c9071bcb9734a0eac55d18a153949"
        proxy = "0x1b2676D32E2f7430a564DD4560641F990dFE3D6a"
        signature = "0x439370b1"

        deposit_eth_function = self._get_function_by_signature(
            network, proxy, contract, signature
        )

        _eth_value = eth_value

        value = self.arbitrum_core._convert_to_ether_format(_eth_value)

        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, value)

        transaction = deposit_eth_function().buildTransaction(tx_param)

        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} bridge {eth_value} ETH from mainnet to arbitrum nova. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )
        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)

    def arb_sushiswap_ETHUSDC(self, private_key: str, eth_value: float) -> None:
        address = self.arbitrum_core._get_address(private_key)

        value_eth = self._randomise_value(eth_value, 1)
        value_usd = float(self._get_eth_price_arbitrum()) * value_eth

        value_with_slippage = self.arbitrum_core._convert_to_mwei_format(
            self._value_with_slippage(value_usd, 1)
        )

        path_weth = self.arbitrum_core._get_checksum_address(
            "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"
        )
        path_usdc = self.arbitrum_core._get_checksum_address(
            "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
        )

        amountOutMin = value_with_slippage
        path = [path_weth, path_usdc]
        to = address
        deadline = self._get_deadline(120)

        network = "arbitrum"
        contract = "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"
        proxy = "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"
        signature = "0x7ff36ab5"

        swap_exact_eth_for_tokens = self._get_function_by_signature(
            network, contract, proxy, signature
        )

        value = self.arbitrum_core._convert_to_ether_format(value_eth)
        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, value)

        transaction = swap_exact_eth_for_tokens(
            amountOutMin, path, to, deadline
        ).buildTransaction(tx_param)

        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} swap {round(eth_value, 4)} ETH to {round(value_usd, 4)} USDC on sushiswap. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )

        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)

    def approve_USDC_sushiswap(self, private_key: str) -> None:
        address = self.arbitrum_core._get_address(private_key)

        network = "arbitrum"
        contract = "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"
        proxy = "0x1eFB3f88Bc88f03FD1804A5C53b7141bbEf5dED8"
        signature = "0x095ea7b3"

        approve_usdc_function = self._get_function_by_signature(
            network, proxy, contract, signature
        )

        approve_address = self.arbitrum_core._get_checksum_address(
            "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"
        )
        amount = 115792089237316195423570985008687907853269984665640564039457584007913129639935

        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, 0)
        transaction = approve_usdc_function(approve_address, amount).buildTransaction(
            tx_param
        )
        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} approve USDC on sushi swap. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )
        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)

    def arb_sushiswap_USDCETH(self, private_key: str, usd_value: float) -> None:
        address = self.arbitrum_core._get_address(private_key)

        network = "arbitrum"
        contract = "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"
        proxy = "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"
        signature = "0x18cbafe5"

        swap_exact_tokens_for_eth = self._get_function_by_signature(
            network, contract, proxy, signature
        )

        value_usd = self._randomise_value(usd_value, 1)
        value_eth = value_usd / float(self._get_eth_price_arbitrum())

        amountIn = self.arbitrum_core._convert_to_mwei_format(value_usd)
        amountOutMin = self.arbitrum_core._convert_to_ether_format(
            self._value_with_slippage(value_eth, 1)
        )

        path_usdc = self.arbitrum_core._get_checksum_address(
            "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
        )
        path_weth = self.arbitrum_core._get_checksum_address(
            "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"
        )
        path = [path_usdc, path_weth]
        to = address
        deadline = self._get_deadline(120)

        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, 0)

        transaction = swap_exact_tokens_for_eth(
            amountIn, amountOutMin, path, to, deadline
        ).buildTransaction(tx_param)

        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} swap {round(value_usd, 4)} USDC to {round(value_eth, 8)} ETH on sushiswap. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )

        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)

    def get_abi_bytecode(self, contract_name: str) -> list | list:
        """Return abi and bytecode from contract json file

        Returns:
            list|list: abi|bytecode
        """
        with open(f"contracts/{contract_name}.json") as jsonFile:
            jsonObject = json.load(jsonFile)
            jsonFile.close()

        abi = jsonObject["abi"]
        bytecode = jsonObject["bytecode"]
        return abi, bytecode

    def deploy_contract(self, private_key: str, contract_name: str) -> None:
        address = self.arbitrum_core._get_address(private_key)
        abi, bytecode = self.get_abi_bytecode(contract_name)
        contract = self.arbitrum_core._web3.eth.contract(abi=abi, bytecode=bytecode)
        
        tx_param = self.arbitrum_core._build_contract_tx_param(private_key, 0)
        transaction = contract.constructor().buildTransaction(tx_param)
        
        tx_hash = self.arbitrum_core._sign_send_get_tx_hash(transaction, private_key)

        fee_cost = self.arbitrum_core._get_fee_cost(tx_hash)

        logger.success(
            f"Wallet {address[:9]} deployed contract {contract_name}.sol. Fee - {round(fee_cost, 2)} | Wait for confirm"
        )

        self.arbitrum_core._wait_for_transaction_receipt(tx_hash)
        self.arbitrum_core._add_random_delay(5, 10)