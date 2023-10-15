"""Forta agent scanning for batched transactions."""

import functools
import logging

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import forta_toolkit.alerts
import forta_toolkit.logging
import forta_toolkit.parsing.logs
import forta_toolkit.parsing.metadata
import forta_toolkit.profiling

import ioseeth.metrics.evasion.morphing
import ioseeth.metrics.evasion.redirection

import src.findings
import src.options

# INIT ########################################################################

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    global PROVIDER
    CHAIN_ID = forta_toolkit.parsing.metadata.load_chain_id(provider=PROVIDER)
    return {}

# METRICS #####################################################################

is_hidden_proxy = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.redirection.is_hidden_proxy)
is_red_pill = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.morphing.is_red_pill)

def score(data: str, bytecode: str, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {'hidden-proxy': 0.5, 'red-pill': 0.5}
    # update scores
    if bytecode:
        __scores['hidden-proxy'] = is_hidden_proxy(data=data, bytecode=bytecode)
        __scores['red-pill'] = is_red_pill(bytecode=bytecode)
    return __scores

# SCANNER #####################################################################

def handle_transaction_factory(
    provider: Web3,
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
        __data = forta_toolkit.parsing.logs.parse_transaction_data(provider=provider, log=log)
        # analyse the transaction
        __scores = score(**__data)
        # hidden proxy
        if __scores['hidden-proxy'] >= min_confidence:
            __findings.append(src.findings.FormatFindingHiddenProxy(
                chain=CHAIN_ID,
                txhash=log.transaction.hash,
                sender=__data['sender'],
                recipient=__data['recipient'],
                confidence=__scores['hidden-proxy']))
        # red pill
        # if __scores['red-pill'] >= min_confidence:
        #     __findings.append(src.findings.FormatFindingRedPill(
        #         chain=CHAIN_ID,
        #         txhash=log.transaction.hash,
        #         sender=__data['sender'],
        #         recipient=__data['recipient'],
        #         confidence=__scores['red-pill']))
        return __findings

    return __handle_transaction

# CONSTANTS ###################################################################

CHAIN_ID = 1
PROVIDER = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# MAIN ########################################################################

forta_toolkit.logging.setup_logger(logging.INFO)
forta_toolkit.parsing.metadata.load_secrets()

# run with the default settings
handle_transaction = handle_transaction_factory(provider=PROVIDER)
