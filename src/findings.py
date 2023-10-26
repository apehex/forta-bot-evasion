"""Format the agent findings into Forta alerts"""

import enum
import logging

from forta_agent import Finding, FindingType, FindingSeverity, EntityType, Label

# TYPES #######################################################################

class EvasionType(enum.IntEnum):
    Unknown = 0
    MetamorphicFactoryDeployment = 1
    MetamorphicMutantDeployment = 2

# METADATA ####################################################################

def get_alert_id(alert_id: int, **kwargs) -> str:
    """Generate the alert id."""
    __alert_id = 'EVASION-{technique}'
    if alert_id == EvasionType.MetamorphicFactoryDeployment:
        __alert_id = __alert_id.format(technique='METAMORPHISM-FACTORY-DEPLOYMENT')
    if alert_id == EvasionType.MetamorphicMutantDeployment:
        __alert_id = __alert_id.format(technique='METAMORPHISM-MUTANT-DEPLOYMENT')
    return __alert_id

def get_alert_name(alert_id: int, sender: str, recipient: str, **kwargs) -> str:
    """Generate the alert name."""
    return 'Metamorphism: {contract} contract deployment'.format(contract='factory' if alert_id == EvasionType.MetamorphicFactoryDeployment else 'mutant')

def get_alert_description(alert_id: int, sender: str, recipient: str, **kwargs) -> str:
    """Generate the alert description."""
    return 'Metamorphism: {sender} is deploying a {contract} contract at {recipient}'.format(
        sender=sender,
        recipient=recipient,
        contract='factory' if alert_id == EvasionType.MetamorphicFactoryDeployment else 'mutant')

def get_alert_type(**kwargs) -> str:
    """Generate the alert type."""
    return FindingType.Suspicious

def get_alert_severity(**kwargs) -> str:
    """Generate the alert type."""
    return FindingSeverity.Info

def get_alert_labels(chain_id: int, alert_id: int, recipient: str, confidence: float, **kwargs) -> str:
    """Generate the alert labels."""
    __labels = []
    # factory
    if alert_id == EvasionType.MetamorphicFactoryDeployment:
        _labels.append(Label({
            'entityType': EntityType.Address,
            'label': "metamorphic-factory-contract",
            'entity': recipient,
            'confidence': round(confidence, 1),
            'metadata': {'chain_id': chain_id}}))
    # mutant
    if alert_id == EvasionType.MetamorphicMutantDeployment:
        _labels.append(Label({
            'entityType': EntityType.Address,
            'label': "metamorphic-contract",
            'entity': recipient,
            'confidence': round(confidence, 1),
            'metadata': {'chain_id': chain_id}}))
    return __labels

def default_get_alert_metadata(chain_id: int, tx_hash: str, sender: str, recipient: str, confidence: float, **kwargs) -> str:
    """Generate the alert metadata."""
    return {
        'chain_id': str(chain_id),
        'tx_hash': tx_hash,
        'from': sender,
        'to': recipient,
        'confidence': str(round(confidence, 1)),}

# FACTORY #####################################################################

def format_finding_factory(
    get_alert_id: callable,
    get_alert_name: callable,
    get_alert_description: callable,
    get_alert_type: callable,
    get_alert_severity: callable,
    get_alert_labels: callable,
    get_alert_log: callable,
    get_alert_metadata: callable=default_get_alert_metadata
) -> Finding:
    """Prepare a formatting function for a specific bot."""
    def __format_finding(**kwargs) -> Finding:
        """Structure all the metadata of the transaction in a Forta "Finding" object."""
        # keep a trace on the node
        logging.info(get_alert_log(**kwargs))
        # raise a Forta network alert
        return Finding({
            'alert_id': get_alert_id(**kwargs),
            'name': get_alert_name(**kwargs),
            'description': get_alert_description(**kwargs),
            'type': get_alert_type(**kwargs),
            'severity': get_alert_severity(**kwargs),
            'metadata': get_alert_metadata(**kwargs),})
    # return the actual function
    return __format_finding

# ACTUAL ######################################################################

format_finding = format_finding_factory(
    get_alert_id=get_alert_id,
    get_alert_name=get_alert_name,
    get_alert_description=get_alert_description,
    get_alert_type=get_alert_type,
    get_alert_severity=get_alert_severity,
    get_alert_labels=get_alert_labels,
    get_alert_log=get_alert_description,)
