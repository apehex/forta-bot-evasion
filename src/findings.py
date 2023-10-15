"""Format the agent findings into Forta alerts"""

import enum
import logging

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# TYPES #######################################################################

class EvasionType(enum.IntEnum):
    Unknown = 0
    HiddenProxy = 1
    RedPill = 2
    Metamorphism = 3
    EventPoisoining = 4

# ALERTS ######################################################################

def alert_id(id) -> str:
    """Generate the alert id."""
    __alert_id = 'EVASION-{technique}'
    if id == EvasionType.HiddenProxy:
        __alert_id = __alert_id.format(technique='HIDDEN-PROXY')
    if id == EvasionType.RedPill:
        __alert_id = __alert_id.format(technique='RED-PILL')
    if id == EvasionType.Metamorphism:
        __alert_id = __alert_id.format(technique='METAMORPHISM')
    if id == EvasionType.EventPoisoining:
        __alert_id = __alert_id.format(technique='EVENT-POISONING')
    return __alert_id

# HIDDEN PROXY ################################################################

def FormatFindingHiddenProxy(
    chain: int,
    txhash: str,
    sender: str,
    recipient: str,
    confidence: float,
) -> Finding:
    """Structure all the metadata of the transaction in a Forta "Finding" object."""
    _labels = []

    # raise a Forta network alert
    _finding = Finding({
        'name': f'Hidden proxy',
        'description': f'{recipient} redirects the execution to a hidden implementation contract',
        'alert_id': alert_id(EvasionType.HiddenProxy),
        'type': FindingType.Suspicious,
        'severity': FindingSeverity.High,
        'metadata': {
            'chain_id': str(chain),
            'from': sender,
            'to': recipient,
            'implementation': '',
            'confidence': round(confidence, 1),},
        'labels': _labels
    })

    # keep a trace on the node
    logging.info(f'{alert_id(EvasionType.HiddenProxy)}: found a call to a hidden proxy in {txhash}')

    return _finding

def FormatFindingRedPill(
    chain: int,
    txhash: str,
    sender: str,
    recipient: str,
    confidence: float,
) -> Finding:
    """Structure all the metadata of the transaction in a Forta "Finding" object."""
    _labels = []

    # raise a Forta network alert
    _finding = Finding({
        'name': f'Hidden proxy',
        'description': f'{recipient} checks whether it is running in a simulation environment',
        'alert_id': alert_id(EvasionType.RedPill),
        'type': FindingType.Suspicious,
        'severity': FindingSeverity.High,
        'metadata': {
            'chain_id': str(chain),
            'from': sender,
            'to': recipient,
            'implementation': '',
            'confidence': round(confidence, 1),},
        'labels': _labels
    })

    # keep a trace on the node
    logging.info(f'{alert_id(EvasionType.RedPill)}: found a call to a red-pill contract in {txhash}')

    return _finding
