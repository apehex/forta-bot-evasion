"""Forta agent scanning for batched transactions."""

import logging
import os
import pprint

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import forta_toolkit.alerts
import forta_toolkit.data
import forta_toolkit.logging
import forta_toolkit.metadata
import forta_toolkit.profiling

import ioseeth.metrics.evasion.morphing
import ioseeth.metrics.evasion.redirection

import src.findings
import src.options

# INIT ########################################################################

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    global WEB3
    CHAIN_ID = forta_toolkit.metadata.load_chain_id(provider=WEB3)
    return {}

# METRICS #####################################################################

def parse(w3: Web3, log: TransactionEvent) -> dict:
    """Extract and format all the required data."""
    __data = {
        'sender': forta_toolkit.data.format_address_with_checksum(getattr(log.transaction, 'from_', '')),
        'receiver': forta_toolkit.data.format_address_with_checksum(getattr(log.transaction, 'to', '')),
        'data': log.transaction.data,
        'bytecode': ''}
    # contract creation
    if not __data['receiver']:
        __data['bytecode'] = __data['data'] # use creation bytecode which contains runtime bytecode
    # exclude transactions that are not involving a contract
    if (len(__data['data']) > 2): # counting the prefix
        __data['bytecode'] = w3.eth.get_code(__data['receiver']).hex()
    return __data

def score(data: str, bytecode: str, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {'hidden-proxy': 0.5, 'red-pill': 0.5}
    # update scores
    if bytecode:
        __scores['hidden-proxy'] = ioseeth.metrics.evasion.redirection.is_hidden_proxy(data=data, bytecode=bytecode)
        __scores['red-pill'] = ioseeth.metrics.evasion.morphing.is_red_pill(bytecode=bytecode)
    return __scores

# SCANNER #####################################################################

def handle_transaction_factory(
    w3: Web3,
    min_confidence: float=src.options.MIN_CONFIDENCE,
    history_size: int=src.options.ALERT_HISTORY_SIZE
) -> callable:
    """Setup the main handler."""

    @forta_toolkit.profiling.timeit
    @forta_toolkit.alerts.alert_history(size=history_size)
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

forta_toolkit.logging.setup_logger(logging.INFO)
forta_toolkit.metadata.load_secrets()

# run with the default settings
handle_transaction = handle_transaction_factory(w3=WEB3)
