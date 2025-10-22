import os
import json
import redis
from dotenv import load_dotenv
from eth_account import Account

from models import User
from utils import (
    w3,
    generate_new_wallet, encrypt_private_key, hash_pin,
    check_pin, decrypt_private_key, get_eth_balance,
    get_token_balance, send_crypto_transaction, is_valid_ethereum_address,
    is_valid_phone_number, call_off_ramp_api,
    estimate_token_transfer_gas, get_eth_balance_for_gas,
    SUPPORTED_TOKEN_SYMBOLS, CURRENT_NETWORK_TOKENS,
    get_crypto_prices_usd # <--- ADDED THIS IMPORT
)

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")

if REDIS_URL:
    r = redis.from_url(REDIS_URL, decode_responses=True)
else:
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB = int(os.getenv("REDIS_DB", 0))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
    
    r = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True
    )

SESSION_EXPIRATION_SECONDS = 30 * 60

# --- USSD Menus ---
MAIN_MENU = """CON Welcome to Crypt:
1. Set up
2. Make a transaction
3. Check details
4. Help
0. Exit"""

SETUP_MENU = """CON Set up:
1. Create Wallet
2. Import Wallet
0. Back"""

CREATE_WALLET_PIN_PROMPT = "CON Enter a 4-digit transaction PIN:\n0. Back"
CREATE_WALLET_PIN_CONFIRM = "CON Confirm your 4-digit transaction PIN:\n0. Back"

IMPORT_WALLET_PRIVATE_KEY_PROMPT = "CON Enter your wallet's private key:\n0. Back"
IMPORT_WALLET_PIN_PROMPT = "CON Enter a 4-digit transaction PIN for your imported wallet:\n0. Back"
IMPORT_WALLET_PIN_CONFIRM = "CON Confirm your 4-digit transaction PIN:\n0. Back"

MAKE_TRANSACTION_MENU = """CON Make a transaction:
1. Send crypto
2. Withdraw crypto
0. Back"""

SEND_CRYPTO_RECIPIENT_PROMPT = "CON Enter recipient's phone number(+2348039...) or wallet address:\n0. Back"

def generate_token_prompt():
    prompt = "CON Choose token to send:\n"
    prompt += "1. ETH\n"
    
    other_tokens = sorted([t for t in SUPPORTED_TOKEN_SYMBOLS if t != 'ETH'])
    for i, token_symbol in enumerate(other_tokens):
        prompt += f"{i + 2}. {token_symbol}\n"
    
    prompt += "0. Back"
    return prompt

SEND_CRYPTO_AMOUNT_PROMPT = "CON Enter amount to send:\n0. Back"
SEND_CRYPTO_PIN_PROMPT = "CON Enter your transaction PIN to confirm:\n0. Back"
SEND_CRYPTO_GAS_APPROVAL = "CON Gas fee: {gas_cost:.6f} ETH\n1. Confirm transaction\n2. Cancel transaction\n0. Back"

WITHDRAW_CRYPTO_BANK_SELECTION = """CON Choose your bank:
1. Bank A
2. Bank B
3. Other
0. Back"""
WITHDRAW_CRYPTO_ACCOUNT_NUMBER_PROMPT = "CON Enter bank account number:\n0. Back"
WITHDRAW_CRYPTO_AMOUNT_PROMPT = "CON Enter amount to withdraw (Naira):\n0. Back"
WITHDRAW_CRYPTO_PIN_PROMPT = "CON Enter your transaction PIN to confirm:\n0. Back"

CHECK_DETAILS_MENU = """CON Check details:
1. Check wallet balance
2. Check wallet address
3. Show private key
0. Back"""

CHECK_DETAILS_PIN_PROMPT = "CON Enter your transaction PIN:\n0. Back"
PRIVATE_KEY_WARNING_PROMPT = "CON WARNING: Sharing your private key can lead to loss of funds. Are you sure you want to view it? (Type YES to confirm)\n0. Back"

HELP_MENU = """END Help:
EasiCrypt allows you to send, withdraw, and check your crypto.
- Set up: Create or import a wallet.
- Make a transaction: Send crypto to another user or withdraw to fiat.
- Check details: View your wallet balance, address, or private key.
For more assistance, contact support."""


def get_menu_text(menu_key):
    if menu_key == 'send_crypto_token_prompt':
        return generate_token_prompt()
    elif menu_key in ['check_balance_pin_prompt', 'check_address_pin_prompt', 'show_private_key_pin_prompt']:
        return CHECK_DETAILS_PIN_PROMPT
    return globals().get(menu_key.upper(), MAIN_MENU)


# --- Session Helpers ---
def get_ussd_session(session_id):
    session_data = r.get(session_id)
    if session_data:
        r.expire(session_id, SESSION_EXPIRATION_SECONDS) 
        return json.loads(session_data)
    return None

def set_ussd_session(session_id, session_data):
    r.setex(session_id, SESSION_EXPIRATION_SECONDS, json.dumps(session_data))

def delete_ussd_session(session_id):
    r.delete(session_id)


# --- USSD Handler ---
def handle_ussd_request(session_id, phone_number, full_text_input):
    """
    Processes a USSD request and returns the appropriate response.
    full_text_input is the complete string provided by the USSD gateway (e.g., "1*1*1234").
    """
    session = get_ussd_session(session_id)

    if not session:
        session = {
            'phone_number': phone_number,
            'current_menu': 'main_menu',
            'menu_history': [],
            'data': {}
        }
        current_user_input = full_text_input
    else:
        current_user_input = full_text_input.split('*')[-1] if '*' in full_text_input else full_text_input

    current_menu_key = session['current_menu']
    menu_history = session['menu_history']
    data = session['data']

    if current_user_input == '0':
        if current_menu_key == 'main_menu':
            delete_ussd_session(session_id)
            return "END Thank you for using EasiCrypt."
        elif current_menu_key == 'show_private_key_pin_prompt' and data.get('private_key_confirmed'):
            delete_ussd_session(session_id)
            return "END Private key viewing cancelled."
        else:
            if menu_history:
                session['current_menu'] = menu_history.pop()
            else:
                session['current_menu'] = 'main_menu'
            session['data'] = {}
            set_ussd_session(session_id, session)
            return get_menu_text(session['current_menu'])

    previous_menu_key = current_menu_key

    # MAIN MENU handling
    if current_menu_key == 'main_menu':
        if current_user_input == '1':
            session['current_menu'] = 'setup_menu'
        elif current_user_input == '2':
            user = User.objects(phone_number=phone_number).first()
            if not user:
                delete_ussd_session(session_id)
                return "END You need to set up a wallet first. Dial again and choose option 1."
            session['current_menu'] = 'make_transaction_menu'
        elif current_user_input == '3':
            user = User.objects(phone_number=phone_number).first()
            if not user:
                delete_ussd_session(session_id)
                return "END You need to set up a wallet first. Dial again and choose option 1."
            session['current_menu'] = 'check_details_menu'
        elif current_user_input == '4':
            delete_ussd_session(session_id)
            return HELP_MENU
        else:
            set_ussd_session(session_id, session)
            return MAIN_MENU

    # SETUP MENU handling
    elif current_menu_key == 'setup_menu':
        if current_user_input == '1':
            user = User.objects(phone_number=phone_number).first()
            if user:
                session['current_menu'] = previous_menu_key
                set_ussd_session(session_id, session)
                return "CON You already have a wallet linked to this number. Please go back (0) or try another option." + SETUP_MENU[3:]
            session['current_menu'] = 'create_wallet_pin_prompt'
        elif current_user_input == '2':
            user = User.objects(phone_number=phone_number).first()
            if user:
                session['current_menu'] = previous_menu_key
                set_ussd_session(session_id, session)
                return "CON You already have a wallet linked to this number. Please go back (0) or try another option." + SETUP_MENU[3:]
            session['current_menu'] = 'import_wallet_private_key_prompt'
        else:
            set_ussd_session(session_id, session) 
            return SETUP_MENU 

    # --- Create Wallet ---
    elif current_menu_key == 'create_wallet_pin_prompt':
        if len(current_user_input) == 4 and current_user_input.isdigit():
            data['new_pin'] = current_user_input
            session['current_menu'] = 'create_wallet_pin_confirm'
        else:
            set_ussd_session(session_id, session)
            return "CON Invalid PIN. Enter a 4-digit PIN:\n0. Back"

    elif current_menu_key == 'create_wallet_pin_confirm':
        if current_user_input == data['new_pin']:
            wallet_address, private_key_bytes = generate_new_wallet()
            encrypted_private_key = encrypt_private_key(private_key_bytes)
            pin_hash = hash_pin(data['new_pin'])

            user = User(
                phone_number=phone_number,
                wallet_address=wallet_address,
                encrypted_private_key=encrypted_private_key,
                pin_hash=pin_hash
            )
            user.save()
            delete_ussd_session(session_id)
            return f"END Wallet created! Your address: {wallet_address}. Please keep your PIN safe."
        else:
            data.pop('new_pin', None)
            session['current_menu'] = 'create_wallet_pin_prompt'
            set_ussd_session(session_id, session)
            return "CON PINs do not match. Enter a 4-digit transaction PIN:\n0. Back"

    # --- Import Wallet ---
    elif current_menu_key == 'import_wallet_private_key_prompt':
        try:
            cleaned_key = current_user_input.strip().lower().replace("0x", "")
            
            if len(cleaned_key) != 64 or any(c not in "0123456789abcdef" for c in cleaned_key):
                raise ValueError("Invalid private key format")

            private_key_bytes_from_input = bytes.fromhex(cleaned_key)
            acct = Account.from_key(private_key_bytes_from_input)
            
            data['imported_address'] = acct.address
            data['imported_private_key_hex'] = cleaned_key
            
            session['current_menu'] = 'import_wallet_pin_prompt'
        
        except Exception as e:
            print(f"Error importing private key: {e}")
            set_ussd_session(session_id, session)
            return "CON Invalid private key. Please enter a valid private key:\n0. Back"

    elif current_menu_key == 'import_wallet_pin_prompt':
        if len(current_user_input) == 4 and current_user_input.isdigit():
            data['new_pin'] = current_user_input
            session['current_menu'] = 'import_wallet_pin_confirm'
        else:
            set_ussd_session(session_id, session) 
            return "CON Invalid PIN. Enter a 4-digit PIN:\n0. Back"

    elif current_menu_key == 'import_wallet_pin_confirm':
        if current_user_input == data['new_pin']:
            private_key_bytes = bytes.fromhex(data['imported_private_key_hex'])
            encrypted_private_key = encrypt_private_key(private_key_bytes)
            pin_hash = hash_pin(data['new_pin'])

            user = User(
                phone_number=phone_number,
                wallet_address=data['imported_address'],
                encrypted_private_key=encrypted_private_key,
                pin_hash=pin_hash
            )
            user.save()
            delete_ussd_session(session_id)
            return f"END Wallet imported! Your address: {data['imported_address']}. Please keep your PIN safe."
        else:
            data.pop('new_pin', None)
            session['current_menu'] = 'import_wallet_pin_prompt'
            set_ussd_session(session_id, session)
            return "CON PINs do not match. Enter a 4-digit transaction PIN:\n0. Back"

    # --- Make Transaction ---
    elif current_menu_key == 'make_transaction_menu':
        if current_user_input == '1':
            session['current_menu'] = 'send_crypto_recipient_prompt'
        elif current_user_input == '2':
            user = User.objects(phone_number=phone_number).first()
            if not user:
                delete_ussd_session(session_id)
                return "END You need a wallet to withdraw crypto. Please set one up."
            session['current_menu'] = 'withdraw_crypto_bank_selection'
        else:
            set_ussd_session(session_id, session)
            return MAKE_TRANSACTION_MENU

    # --- Send Crypto ---
    elif current_menu_key == 'send_crypto_recipient_prompt':
        data['recipient_input'] = current_user_input
        session['current_menu'] = 'send_crypto_token_prompt'
        set_ussd_session(session_id, session)
        return get_menu_text('send_crypto_token_prompt')

    elif current_menu_key == 'send_crypto_token_prompt':
        token_options = ['ETH'] + sorted([t for t in SUPPORTED_TOKEN_SYMBOLS if t != 'ETH'])
        try:
            choice_index = int(current_user_input)
            if 1 <= choice_index <= len(token_options):
                data['token_symbol'] = token_options[choice_index - 1]
                session['current_menu'] = 'send_crypto_amount_prompt'
            else:
                raise ValueError
        except ValueError:
            set_ussd_session(session_id, session)
            return "CON Invalid selection. Please choose a valid token:\n" + generate_token_prompt()
        
        set_ussd_session(session_id, session)
        return SEND_CRYPTO_AMOUNT_PROMPT

    elif current_menu_key == 'send_crypto_amount_prompt':
        try:
            amount = float(current_user_input)
            if amount <= 0:
                raise ValueError
            data['amount'] = amount
            session['current_menu'] = 'send_crypto_pin_prompt'
            set_ussd_session(session_id, session)
            return SEND_CRYPTO_PIN_PROMPT
        except ValueError:
            set_ussd_session(session_id, session)
            return "CON Invalid amount. Enter a positive number:\n0. Back"

    elif current_menu_key == 'send_crypto_pin_prompt':
        user = User.objects(phone_number=phone_number).first()
        if not user or not check_pin(current_user_input, user.pin_hash):
            delete_ussd_session(session_id)
            return "END Invalid PIN. Transaction cancelled."

        recipient_input = data['recipient_input']
        token_symbol = data['token_symbol']
        amount = data['amount']

        recipient_address = None
        if is_valid_ethereum_address(recipient_input):
            recipient_address = recipient_input
        elif is_valid_phone_number(recipient_input):
            recipient_user = User.objects(phone_number=recipient_input).first()
            if recipient_user:
                recipient_address = recipient_user.wallet_address
            else:
                delete_ussd_session(session_id)
                return f"END Recipient {recipient_input} not registered with EasiCrypt. Please use a wallet address or ask them to register."
        else:
            delete_ussd_session(session_id)
            return "END Invalid recipient. Please provide a valid phone number or wallet address."
        
        data['resolved_recipient_address'] = recipient_address 

        eth_balance_wei = get_eth_balance_for_gas(user.wallet_address)
        eth_balance_eth = eth_balance_wei / 10**18
        
        if token_symbol != 'ETH':
            try:
                gas_estimate, gas_cost_eth = estimate_token_transfer_gas(
                    user.wallet_address, recipient_address, amount, token_symbol
                )
                data['gas_cost_eth'] = gas_cost_eth
                data['gas_estimate'] = gas_estimate
                
                if eth_balance_eth < gas_cost_eth:
                    delete_ussd_session(session_id)
                    return f"END Insufficient ETH for gas fees. You need {gas_cost_eth:.6f} ETH but only have {eth_balance_eth:.6f} ETH."
                
                session['current_menu'] = 'send_crypto_gas_approval'
                set_ussd_session(session_id, session) # Save session state to Redis
                return SEND_CRYPTO_GAS_APPROVAL.format(gas_cost=gas_cost_eth)
            except Exception as e:
                delete_ussd_session(session_id)
                print(f"Gas estimation error: {e}")
                return "END Failed to estimate gas fees. Please try again later."

        if token_symbol == 'ETH':
            gas_cost_eth = 21000 * w3.eth.gas_price / 10**18
            total_cost_eth = amount + gas_cost_eth
            
            if eth_balance_eth < total_cost_eth:
                delete_ussd_session(session_id)
                return f"END Insufficient ETH balance. You need {total_cost_eth:.6f} ETH but only have {eth_balance_eth:.6f} ETH."
            
            data['gas_cost_eth'] = gas_cost_eth
            session['current_menu'] = 'send_crypto_gas_approval'
            set_ussd_session(session_id, session)
            return SEND_CRYPTO_GAS_APPROVAL.format(gas_cost=gas_cost_eth)

    elif current_menu_key == 'send_crypto_gas_approval':
        user = User.objects(phone_number=phone_number).first()
        if not user:
            delete_ussd_session(session_id)
            return "END Session expired or user not found."

        if current_user_input == '1':
            sender_private_key_bytes = decrypt_private_key(user.encrypted_private_key)
            recipient_input = data['recipient_input']
            resolved_recipient_address = data['resolved_recipient_address']
            token_symbol = data['token_symbol']
            amount = data['amount']
            
            try:
                tx_hash = send_crypto_transaction(sender_private_key_bytes, resolved_recipient_address, amount, token_symbol)
                delete_ussd_session(session_id)
                return f"END {amount} {token_symbol} sent to {recipient_input}. Tx: {tx_hash}"
            except Exception as e:
                delete_ussd_session(session_id)
                print(f"Transaction error: {e}")
                error_msg = str(e)
                if "insufficient funds" in error_msg.lower():
                    return "END Transaction failed: Insufficient funds or gas fees."
                elif "nonce" in error_msg.lower():
                    return "END Transaction failed: Please try again."
                else:
                    return "END Transaction failed. Please try again later."
        elif current_user_input == '2':
            delete_ussd_session(session_id)
            return "END Transaction cancelled."
        else:
            set_ussd_session(session_id, session)
            return SEND_CRYPTO_GAS_APPROVAL.format(gas_cost=data['gas_cost_eth'])

    # --- Withdraw Crypto (Off-ramp) ---
    elif current_menu_key == 'withdraw_crypto_bank_selection':
        data['bank_selection'] = current_user_input
        session['current_menu'] = 'withdraw_crypto_account_number_prompt'
        set_ussd_session(session_id, session)
        return WITHDRAW_CRYPTO_ACCOUNT_NUMBER_PROMPT

    elif current_menu_key == 'withdraw_crypto_account_number_prompt':
        data['bank_account_number'] = current_user_input
        session['current_menu'] = 'withdraw_crypto_amount_prompt'
        set_ussd_session(session_id, session)
        return WITHDRAW_CRYPTO_AMOUNT_PROMPT

    elif current_menu_key == 'withdraw_crypto_amount_prompt':
        try:
            amount = float(current_user_input)
            if amount <= 0:
                raise ValueError
            data['withdraw_amount'] = amount
            session['current_menu'] = 'withdraw_crypto_pin_prompt'
            set_ussd_session(session_id, session)
            return WITHDRAW_CRYPTO_PIN_PROMPT
        except ValueError:
            set_ussd_session(session_id, session)
            return "CON Invalid amount. Enter a positive number:\n0. Back"

    elif current_menu_key == 'withdraw_crypto_pin_prompt':
        user = User.objects(phone_number=phone_number).first()
        if not user or not check_pin(current_user_input, user.pin_hash):
            delete_ussd_session(session_id)
            return "END Invalid PIN. Withdrawal cancelled."

        try:
            tx_hash = call_off_ramp_api(data['withdraw_amount'], data['bank_account_number'], user.wallet_address)
            delete_ussd_session(session_id)
            return f"END ₦{data['withdraw_amount']} successfully withdrawn to {data['bank_account_number']}. Tx: {tx_hash}"
        except Exception as e:
            delete_ussd_session(session_id)
            print(f"Off-ramp error: {e}")
            return "END Withdrawal failed. Please try again later."


    # --- Check Details ---
    elif current_menu_key == 'check_details_menu':
        user = User.objects(phone_number=phone_number).first()
        if not user:
            delete_ussd_session(session_id)
            return "END Error: Wallet not found. Please set up."

        if current_user_input == '1':
            session['current_menu'] = 'check_balance_pin_prompt'
        elif current_user_input == '2':
            session['current_menu'] = 'check_address_pin_prompt'
        elif current_user_input == '3':
            session['current_menu'] = 'show_private_key_pin_prompt'
        else:
            set_ussd_session(session_id, session)
            return CHECK_DETAILS_MENU

    # --- Check Balance ---
    elif current_menu_key == 'check_balance_pin_prompt':
        user = User.objects(phone_number=phone_number).first()
        if not user or not check_pin(current_user_input, user.pin_hash):
            delete_ussd_session(session_id)
            return "END Invalid PIN. Access denied."

        balance_message = "END Wallet Balance:\n"
        
        all_token_symbols_for_price = list(SUPPORTED_TOKEN_SYMBOLS)
        crypto_prices_usd = get_crypto_prices_usd(all_token_symbols_for_price)

        eth_balance = get_eth_balance(user.wallet_address)
        eth_price = crypto_prices_usd.get('ETH', 0.0)
        eth_usd_value = eth_balance * eth_price
        balance_message += f"ETH: {eth_balance:.4f} (${eth_usd_value:.2f})\n"

        other_tokens_sorted = sorted([t for t in SUPPORTED_TOKEN_SYMBOLS if t != 'ETH'])
        for token_symbol in other_tokens_sorted:
            try:
                token_balance = get_token_balance(user.wallet_address, token_symbol)
                token_price = crypto_prices_usd.get(token_symbol, 0.0)
                token_usd_value = float(token_balance) * token_price

                if CURRENT_NETWORK_TOKENS[token_symbol]['decimals'] == 6:
                    balance_message += f"{token_symbol}: {token_balance:.2f} (${token_usd_value:.2f})\n"
                else:
                    balance_message += f"{token_symbol}: {token_balance:.4f} (${token_usd_value:.2f})\n"
            except Exception as e:
                print(f"Error fetching {token_symbol} balance or price: {e}")
                balance_message += f"{token_symbol}: Error\n"


        balance_message += "(Balances are on Base network)"
        delete_ussd_session(session_id)
        return balance_message

    # --- Check Address ---
    elif current_menu_key == 'check_address_pin_prompt':
        user = User.objects(phone_number=phone_number).first()
        if not user or not check_pin(current_user_input, user.pin_hash):
            delete_ussd_session(session_id)
            return "END Invalid PIN. Access denied."

        delete_ussd_session(session_id)
        return f"END Your wallet address: {user.wallet_address}"

    # --- Show Private Key ---
    elif current_menu_key == 'show_private_key_pin_prompt':
        user = User.objects(phone_number=phone_number).first()
        if not user:
            delete_ussd_session(session_id)
            return "END Session expired or user not found."

        if 'private_key_confirmed' not in data:
            if check_pin(current_user_input, user.pin_hash):
                data['private_key_confirmed'] = True
                set_ussd_session(session_id, session)
                return PRIVATE_KEY_WARNING_PROMPT
            else:
                delete_ussd_session(session_id)
                return "END Invalid PIN. Access denied."
        else:
            if current_user_input.upper() == 'YES':
                private_key_bytes = decrypt_private_key(user.encrypted_private_key)
                delete_ussd_session(session_id)
                return f"END Your Private Key (handle with extreme care!): {private_key_bytes.hex()}"
            else:
                delete_ussd_session(session_id)
                return "END Private key viewing cancelled."

    if session['current_menu'] != previous_menu_key:
        menu_history.append(previous_menu_key)
        
    set_ussd_session(session_id, session)

    return get_menu_text(session['current_menu'])