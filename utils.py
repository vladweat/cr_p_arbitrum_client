import config

from loguru import logger
from arbitrum_core import ArbitrumCore
from arbitrum_client import ArbitrumClient

def get_private_keys() -> list:
    try:
        with open("private_keys.txt", "r") as file:
            keys = file.read().splitlines()
        return keys

    except Exception as e:
        logger.error(e)
        
def bridge_from_mainnet(eth_value: float):
    core = ArbitrumCore(run=config.RUN_SCRIPT, network='mainnet')
    client = ArbitrumClient(core)
    
    keys_list = get_private_keys()
    for key in keys_list:
        client.bridge_mainnet_to_arb_one(key, eth_value)
        client.bridge_mainnet_to_arb_nova(key, eth_value)
        
def arb_sushiswap(eth_value: float, usd_value: float):
    core = ArbitrumCore(run=config.RUN_SCRIPT, network='arbitrum')
    client = ArbitrumClient(core)
    
    keys_list = get_private_keys()
    for key in keys_list:
        client.arb_sushiswap_ETHUSDC(key, eth_value)
        client.approve_USDC_sushiswap(key)
        client.arb_sushiswap_USDCETH(key, usd_value)
        
def arb_deploy_contract(contract_name: str):
    core = ArbitrumCore(run=config.RUN_SCRIPT, network='arbitrum')
    client = ArbitrumClient(core)

    keys_list = get_private_keys()
    for key in keys_list:
        client.deploy_contract(key, contract_name)