"""Evaluate the probability that multiple transfers were bundled in a transaction."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.indicators.proxy
import src.indicators.token
import src.metrics.probabilities
import src.metrics.normal.proxy
import src.options

# HIDDEN PROXY ################################################################

# is redirecting execution ?
# no => out
# yes
    # is standard proxy ?
        # yes
            # is their an address in the implementation slot?
                # yes
                    # is the implementation contract empty?
                        # yes => weird (check contract age)
                        # no => is it the one called?
                # no => weird (view contract age)
        # no
            # is it a token?
                # yes => weird (token + delegate)

def is_hidden_proxy(
    data: str,
    bytecode: str
) -> float:
    """Evaluate that a contract is redirecting execution."""
    __scores = []
    # requirement: must redirect execution
    __scores.append(src.metrics.probabilities.indicator_to_probability(
        indicator=src.metrics.normal.proxy.is_redirecting_execution_to_another_contract(data=data, bytecode=bytecode) >= 0.7,
        true_score=0.5, # does not say whether the contract is malicious
        false_score=0.)) # cannot be a hidden a proxy if it's not even a proxy
    # std proxies... should follow standards
    # tokens shouldn't redirect
    __scores.append(src.metrics.probabilities.indicator_to_probability(
        indicator=src.indicators.token.bytecode_has_any_token_interface(bytecode=bytecode, threshold=0.9),
        true_score=0.8, # tokens should never happen redirect
        false_score=0.5)) # there are other types of hidden proxies
    return src.metrics.probabilities.conflation(__scores)
