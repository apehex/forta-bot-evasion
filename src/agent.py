"""Forta agent scanning for batched transactions."""

import functools
import logging
import pickle

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import toolblocks.alerts
import toolblocks.indexing.parquet
import toolblocks.logging
import toolblocks.parsing.env
import toolblocks.preprocessing
import toolblocks.profiling

import src.findings
import src.options
import src.scoring

# CONSTANTS ###################################################################

CHAIN_ID = 1
PROVIDER = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# INIT ########################################################################

toolblocks.logging.setup_logger(level=logging.INFO, version=toolblocks.parsing.env.get_bot_version())
# toolblocks.parsing.env.load_secrets()

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    global PROVIDER
    CHAIN_ID = toolblocks.parsing.env.load_chain_id(provider=PROVIDER)
    return {}

# SCRAPING ####################################################################

get_code = functools.lru_cache(maxsize=2048)(PROVIDER.eth.get_code)

# SCANNER #####################################################################

def handle_transaction_factory(
    provider: Web3,
    min_confidence: float=src.options.MIN_CONFIDENCE,
    history_size: int=src.options.ALERT_HISTORY_SIZE,
    chunk_size: int=src.options.DATABASE_CHUNK_SIZE
) -> callable:
    """Setup the main handler."""
    global CHAIN_ID

    @toolblocks.profiling.timeit
    @toolblocks.alerts.alert_history(size=history_size)
    @toolblocks.preprocessing.parse_forta_arguments
    @toolblocks.indexing.parquet.export_to_database(chain_id=CHAIN_ID, dataset='contracts', chunksize=chunk_size, compress=True)
    @toolblocks.indexing.parquet.import_from_database(chain_id=CHAIN_ID, dataset='contracts')
    def __handle_transaction(transaction: dict, logs: list, traces: list, dataset: 'pyarrow.dataset.FileSystemDataset', **kwargs) -> list:
        """Main function called by the node daemon.
        Must be wrapped by a preprocessor to parse the composite Forta object into its constituent transaction, logs and traces."""
        global CHAIN_ID
        # result: list of alerts
        __findings = []
        # iterate over event logs
        for __l in logs:
            # analyse the transaction
            __scores = src.scoring.score_log(log=__l, chain_id=CHAIN_ID)
            # iterate over the scan results
            for __id, __score in __scores.items():
                if __score >= min_confidence:
                    # keep a trace on the node
                    logging.info(src.findings.get_alert_description(chain_id=CHAIN_ID, alert_id=__id, transaction=transaction, log=__l, trace={}))
                    # raise an alert
                    __findings.append(src.findings.format_finding(chain_id=CHAIN_ID, alert_id=__id, confidence=__score, transaction=transaction, log=__l, trace={}))
        # iterate over each subtrace
        for __t in traces:
            # analyse the transaction
            __scores = src.scoring.score_trace(trace=__t, chain_id=CHAIN_ID, dataset=dataset)
            # iterate over the scan results
            for __id, __score in __scores.items():
                if __score >= min_confidence:
                    # keep a trace on the node
                    logging.info(src.findings.get_alert_description(chain_id=CHAIN_ID, alert_id=__id, transaction=transaction, log={}, trace=__t))
                    # raise an alert
                    __findings.append(src.findings.format_finding(chain_id=CHAIN_ID, alert_id=__id, confidence=__score, transaction=transaction, log={}, trace=__t))
        # compare to historic data
        # raise the alerts
        return __findings

    return __handle_transaction

# MAIN ########################################################################

# run with the default settings
handle_transaction = handle_transaction_factory(provider=PROVIDER)
