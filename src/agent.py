"""Forta agent scanning for batched transactions."""

import logging
import os
import pprint

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

from evmdasm.disassembler import EvmBytecode

import src.findings
import src.metrics.evasion.morphing
import src.metrics.evasion.redirection
import src.options
import src.stats
import src.utils

# INIT ########################################################################

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    try:
        CHAIN_ID = int(os.environ.get('FORTA_CHAIN_ID', '') or WEB3.eth.chain_id)
        os.environ['FORTA_CHAIN_ID'] = str(CHAIN_ID)
        logging.info(f'set chain id to {CHAIN_ID}')
    except Exception as e:
        logging.error(f'error getting chain id (kept to {CHAIN_ID})')
        raise e
    return {}

# METRICS #####################################################################

def parse(w3: Web3, log: TransactionEvent) -> dict:
    """Extract and format all the required data."""
    __data = {
        'sender': src.utils.format_address_with_checksum(getattr(log.transaction, 'from_', '')),
        'receiver': src.utils.format_address_with_checksum(getattr(log.transaction, 'to', '')),
        'data': log.transaction.data,
        'assembly': ''}
    # contract creation
    if not __data['receiver']:
        __data['assembly'] = __data['data'] # use creation bytecode which contains runtime bytecode
    # exclude transactions that are not involving a contract
    if (len(__data['data']) >= 6): # prefix + selector
        __assembly = EvmBytecode(w3.eth.get_code(__data['receiver'])).disassemble()
        __data['assembly'] = __assembly.as_string
    return __data

def score(data: str, assembly: str, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {'hidden-proxy': 0.5, 'red-pill': 0.5}
    # update scores
    if assembly:
        __scores['hidden-proxy'] = src.metrics.evasion.redirection.is_hidden_proxy(data=data, bytecode=assembly)
        __scores['red-pill'] = src.metrics.evasion.morphing.is_red_pill(bytecode=assembly)
    return __scores

# SCANNER #####################################################################

def handle_transaction_factory(
    w3: Web3,
    min_confidence: float=src.options.MIN_CONFIDENCE,
    history_size: int=src.options.ALERT_HISTORY_SIZE
) -> callable:
    """Setup the main handler."""

    @src.utils.timeit
    @src.stats.alert_history(size=history_size)
    def __handle_transaction(log: TransactionEvent) -> list:
        """Main function called on the logs gathered by the Forta network."""
        global CHAIN_ID
        # result: list of alerts
        __findings = []
        __data = parse(w3=w3, log=log)
        # analyse the transaction
        __scores = score(**__data)
        # hidden proxy
        if __scores['hidden-proxy'] >= min_confidence:
            __findings.append(src.findings.FormatFindingHiddenProxy(
                chain=CHAIN_ID,
                txhash=log.transaction.hash,
                sender=__data['sender'],
                receiver=__data['receiver'],
                confidence=__scores['hidden-proxy']))
        # red pill
        # if __scores['red-pill'] >= min_confidence:
        #     __findings.append(src.findings.FormatFindingRedPill(
        #         chain=CHAIN_ID,
        #         txhash=log.transaction.hash,
        #         sender=__data['sender'],
        #         receiver=__data['receiver'],
        #         confidence=__scores['red-pill']))
        return __findings

    return __handle_transaction

# CONSTANTS ###################################################################

CHAIN_ID = 1
WEB3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# MAIN ########################################################################

src.utils.setup_logger(logging.INFO)
src.utils.load_secrets()

# run with the default settings
handle_transaction = handle_transaction_factory(w3=WEB3)
