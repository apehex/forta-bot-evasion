"""Evaluate the probability that multiple transfers were bundled in a transaction."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.indicators.generic
import src.metrics.probabilities
import src.options

# CONSTANTS ###################################################################

UNUSUAL_OPCODES = ('BLOCKHASH', 'DIFFICULTY')

RED_PILL_OPCODES = ('COINBASE',)

# RED PILL ####################################################################

def is_red_pill(
    bytecode: str,
) -> float:
    """Evaluate the probability that a contract is trying to evade simulation environments."""
    __scores = []
    # opcodes used to detect simulation environments
    __scores.append(src.metrics.probabilities.indicator_to_probability(
        indicator=src.indicators.generic.bytecode_has_specific_opcodes(bytecode=bytecode, opcodes=RED_PILL_OPCODES, check=any),
        true_score=0.7,
        false_score=0.5))
    return src.metrics.probabilities.conflation(__scores)
