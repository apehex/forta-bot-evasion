"""Forta agent scanning for batched transactions."""

import functools
import logging
import pprint

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import forta_toolkit.alerts
import forta_toolkit.logging
import forta_toolkit.parsing.traces
import forta_toolkit.parsing.metadata
import forta_toolkit.profiling

import ioseeth.metrics.evasion.morphing.metamorphism

import src.findings
import src.options

# CONSTANTS ###################################################################

CHAIN_ID = 1
PROVIDER = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# INIT ########################################################################

forta_toolkit.logging.setup_logger(logging.DEBUG)
forta_toolkit.parsing.metadata.load_secrets()

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    global PROVIDER
    CHAIN_ID = forta_toolkit.parsing.metadata.load_chain_id(provider=PROVIDER)
    return {}

# SCRAPING ####################################################################

get_code = functools.lru_cache(maxsize=2048)(PROVIDER.eth.get_code)

# METRICS #####################################################################

is_trace_factory_contract_creation = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.morphing.metamorphism.is_trace_factory_contract_creation)
is_trace_mutant_contract_creation = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.morphing.metamorphism.is_trace_mutant_contract_creation)

def score(data: str, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {src.findings.EvasionType.MetamorphicFactoryDeployment: 0.5, src.findings.EvasionType.MetamorphicMutantDeployment: 0.5}
    # update scores
    __scores[src.findings.EvasionType.MetamorphicFactoryDeployment] = is_trace_factory_contract_creation(action=data['type'], creation_bytecode=data['input'], runtime_bytecode=data['output'])
    __scores[src.findings.EvasionType.MetamorphicMutantDeployment] = is_trace_mutant_contract_creation(action=data['type'], creation_bytecode=data['input'], runtime_bytecode=data['output'])
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
        # iterate over each subtrace
        for __t in log.traces:
            # parse
            __data = forta_toolkit.parsing.traces.parse_trace_data(trace=__t)
            # analyse the transaction
            __scores = score(data=__data)
            # logging.debug(__scores)
            # iterate over the scan results
            for __id, __score in __scores.items():
                if __score > 0.5:
                    logging.debug('{hash}: {id} with probability {probability}'.format(
                        hash=__data['hash'],
                        id=__id,
                        probability=__score))
                if __score >= min_confidence:
                    __findings.append(src.findings.format_finding(
                        alert_id=__id,
                        chain_id=CHAIN_ID,
                        tx_hash=__data['hash'],
                        sender=__data['from'],
                        recipient=__data['to'],
                        confidence=__score))
        return __findings

    return __handle_transaction

# MAIN ########################################################################

# run with the default settings
handle_transaction = handle_transaction_factory(provider=PROVIDER)

# TODO ########################################################################

# import forta_toolkit.parsing.transaction

# import ioseeth.metrics.evasion.morphing.logic_bomb
# import ioseeth.metrics.evasion.redirection

# is_hidden_proxy = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.redirection.is_hidden_proxy)
# is_red_pill = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.morphing.logic_bomb.is_red_pill)

# def handle_transaction_factory(
#     provider: Web3,
#     min_confidence: float=src.options.MIN_CONFIDENCE,
#     history_size: int=src.options.ALERT_HISTORY_SIZE
# ) -> callable:
#     """Setup the main handler."""
#     @forta_toolkit.profiling.timeit
#     @forta_toolkit.alerts.alert_history(size=history_size)
#     def __handle_transaction(log: TransactionEvent) -> list:
#         """Main function called on the logs gathered by the Forta network."""
#         global CHAIN_ID
#         # result: list of alerts
#         __findings = []
#         __data = forta_toolkit.parsing.transaction.parse_transaction_data(transaction=log.transaction)
#         # analyse the transaction
#         __scores = score(**__data)
#         # metamorphic contracts
#         hidden proxy
#         if __scores['hidden-proxy'] >= min_confidence:
#             __findings.append(src.findings.FormatFindingHiddenProxy(
#                 chain=CHAIN_ID,
#                 txhash=log.transaction.hash,
#                 sender=__data['sender'],
#                 recipient=__data['recipient'],
#                 confidence=__scores['hidden-proxy']))
#         # red pill
#         if __scores['red-pill'] >= min_confidence:
#             __findings.append(src.findings.FormatFindingRedPill(
#                 chain=CHAIN_ID,
#                 txhash=log.transaction.hash,
#                 sender=__data['sender'],
#                 recipient=__data['recipient'],
#                 confidence=__scores['red-pill']))
#         return __findings
#     return __handle_transaction
