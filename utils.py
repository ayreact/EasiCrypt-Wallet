import os
import re
import json
import bcrypt
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from decimal import Decimal
import requests

load_dotenv()

# --- Web3 Config ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_SECRET_KEY")
if ENCRYPTION_KEY is None:
    raise ValueError("ENCRYPTION_SECRET_KEY not set in .env file")

fernet = Fernet(ENCRYPTION_KEY.encode())

RPC_URL = os.getenv("RPC_URL_BASE")
COINGECKO_API_BASE = os.getenv("COINGECKO_API_BASE")
if RPC_URL is None:
    raise ValueError("RPC_URL_BASE not set in .env file")
USE_MAINNET = os.getenv("USE_MAINNET", "False").lower() == "true"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

if not w3.is_connected():
    raise ConnectionError("Failed to connect to Base network RPC. Check your RPC_URL_BASE.")

def is_valid_ethereum_address(address):
    return w3.is_address(address)

def encrypt_private_key(private_key_bytes):
    return fernet.encrypt(private_key_bytes)

def decrypt_private_key(encrypted_key_bytes):
    return fernet.decrypt(encrypted_key_bytes)

def is_valid_phone_number(identifier):
    return re.match(r'^\+?[1-9]\d{6,14}$', identifier) is not None

def hash_pin(pin):
    hashed = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def check_pin(pin, hashed_pin):
    return bcrypt.checkpw(pin.encode('utf-8'), hashed_pin.encode('utf-8'))

def generate_new_wallet():
    acct = Account.create()
    return acct.address, acct.key

def get_eth_balance(address):
    try:
        balance_wei = w3.eth.get_balance(address)
        return float(w3.from_wei(balance_wei, 'ether'))
    except Exception as e:
        print(f"Error fetching ETH balance: {e}")
        return 0.0

# --- Token Config ---
TOKEN_CONFIGS = {
    'MAINNET': {
        'USDC': {'address': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'decimals': 6},
        'DAI': {'address': '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb', 'decimals': 18},
        'LINK': {'address': '0x88Fb150BDc53A65fe94Dea0c9BA0a6dAf8C6e196', 'decimals': 18},
    },
    'TESTNET': {
        'USDC': {'address': '0x081827b8C3Aa05287b5aA2bC3051fbE638F33152', 'decimals': 6},
        'DAI': {'address': '0xAE7BD344982bD507D3dcAa828706D558cf281F13', 'decimals': 18},
        'LINK': {'address': '0xE4aB69C077896252FAFBD49EFD26B5D171A32410', 'decimals': 18},
    }
}

CURRENT_NETWORK_TOKENS = TOKEN_CONFIGS['MAINNET'] if USE_MAINNET else TOKEN_CONFIGS['TESTNET']
SUPPORTED_TOKEN_SYMBOLS = ['ETH'] + list(CURRENT_NETWORK_TOKENS.keys())

try:
    with open('erc20_abi.json', 'r') as abi_file:
        ERC20_ABI = json.load(abi_file)
except FileNotFoundError:
    raise FileNotFoundError("Missing ERC20 ABI file (erc20_abi.json)")

def get_token_balance(address, token_symbol):
    if token_symbol == 'ETH':
        return get_eth_balance(address)
    
    checksum_address = w3.to_checksum_address(address)
    
    token_info = CURRENT_NETWORK_TOKENS.get(token_symbol)
    if not token_info:
        raise ValueError(f"Unsupported token symbol: {token_symbol}")
    
    contract_address = w3.to_checksum_address(token_info['address'])
    decimals = token_info['decimals']
    
    token_contract = w3.eth.contract(address=contract_address, abi=ERC20_ABI)
    balance_raw = token_contract.functions.balanceOf(checksum_address).call()
    return Decimal(balance_raw) / Decimal(10 ** decimals)

def send_crypto_transaction(sender_private_key, recipient_address, amount, token_symbol='ETH'):
    sender_account = w3.eth.account.from_key(sender_private_key)
    nonce = w3.eth.get_transaction_count(sender_account.address)
    gas_price = w3.eth.gas_price

    if token_symbol == 'ETH':
        transaction = {
            'chainId': w3.eth.chain_id,
            'from': sender_account.address,
            'to': recipient_address,
            'value': w3.to_wei(amount, 'ether'),
            'nonce': nonce,
            'gas': 21000,
            'gasPrice': gas_price
        }
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=sender_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return w3.to_hex(tx_hash)
    
    elif token_symbol in CURRENT_NETWORK_TOKENS:
        sender_address = w3.to_checksum_address(sender_account.address)
        recipient_checksum = w3.to_checksum_address(recipient_address)
        
        token_info = CURRENT_NETWORK_TOKENS[token_symbol]
        contract_address = w3.to_checksum_address(token_info['address'])
        decimals = token_info['decimals']
        
        token_contract = w3.eth.contract(address=contract_address, abi=ERC20_ABI)
        amount_raw = int(Decimal(str(amount)) * (10 ** decimals))
        transfer_function = token_contract.functions.transfer(recipient_checksum, amount_raw)
        
        try:
            gas_estimate = transfer_function.estimate_gas({'from': sender_address, 'nonce': nonce})
        except Exception:
            gas_estimate = 100000
        
        transaction = transfer_function.build_transaction({
            'chainId': w3.eth.chain_id,
            'from': sender_address,
            'nonce': nonce,
            'gasPrice': gas_price,
            'gas': gas_estimate
        })
        
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=sender_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return w3.to_hex(tx_hash)
    
    else:
        raise ValueError("Unsupported token symbol.")

def estimate_token_transfer_gas(sender_address, recipient_address, amount, token_symbol):
    sender_checksum = w3.to_checksum_address(sender_address)
    recipient_checksum = w3.to_checksum_address(recipient_address)
    
    token_info = CURRENT_NETWORK_TOKENS.get(token_symbol)
    if not token_info:
        raise ValueError(f"Unsupported token symbol: {token_symbol}")
    
    contract_address = w3.to_checksum_address(token_info['address'])
    decimals = token_info['decimals']
    
    token_contract = w3.eth.contract(address=contract_address, abi=ERC20_ABI)
    amount_raw = int(Decimal(str(amount)) * (10 ** decimals))
    
    try:
        gas_estimate = token_contract.functions.transfer(recipient_checksum, amount_raw).estimate_gas({
            'from': sender_checksum
        })
    except Exception:
        gas_estimate = 100000
    
    gas_price = w3.eth.gas_price
    gas_cost_eth = gas_estimate * gas_price / 10**18
    return gas_estimate, gas_cost_eth

def get_eth_balance_for_gas(address):
    return w3.eth.get_balance(address)

def call_off_ramp_api(amount, bank_details, user_wallet_address):
    print(f"MOCK: Calling off-ramp API for {amount} to {bank_details} from {user_wallet_address}")
    import time
    time.sleep(2)
    mock_tx_hash = "0x" + os.urandom(32).hex()
    return mock_tx_hash


def get_crypto_prices_usd(token_symbols):
    """
    Fetches the current USD prices for a list of crypto token symbols from CoinGecko.
    
    Args:
        token_symbols (list): A list of token symbols (e.g., ['ETH', 'USDC', 'DAI']).
                              'ETH' is mapped to 'ethereum'. Other symbols use their coingecko_id.
                               
    Returns:
        dict: A dictionary where keys are original token symbols and values are their USD prices.
              Returns 0.0 for any token whose price could not be fetched.
              Example: {'ETH': 3800.50, 'USDC': 0.99, 'DAI': 1.01}
    """
    coingecko_ids = []
    symbol_to_id_map = {}

    if 'ETH' in token_symbols:
        coingecko_ids.append('ethereum')
        symbol_to_id_map['ethereum'] = 'ETH'

    for symbol in token_symbols:
        if symbol != 'ETH':
            token_info = CURRENT_NETWORK_TOKENS.get(symbol)
            if token_info and 'coingecko_id' in token_info:
                coingecko_ids.append(token_info['coingecko_id'])
                symbol_to_id_map[token_info['coingecko_id']] = symbol

    if not coingecko_ids:
        return {}

    coingecko_ids = list(set(coingecko_ids))

    params = {
        'ids': ','.join(coingecko_ids),
        'vs_currencies': 'usd'
    }

    prices = {}
    try:
        response = requests.get(COINGECKO_API_BASE, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        for cg_id, original_symbol in symbol_to_id_map.items():
            price = data.get(cg_id, {}).get('usd', 0.0)
            prices[original_symbol] = float(price)
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching prices from CoinGecko: {e}")
        for symbol in token_symbols:
            prices[symbol] = 0.0
            
    final_prices = {}
    for symbol in token_symbols:
        final_prices[symbol] = prices.get(symbol, 0.0)

    return final_prices