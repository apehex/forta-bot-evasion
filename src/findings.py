"""Format the agent findings into Forta alerts"""

import enum
import logging

import forta_agent
import forta_toolkit

# TYPES #######################################################################

class EvasionType(enum.IntEnum):
    Unknown = 0
    MetamorphicFactoryDeployment = 1
    MetamorphicMutantDeployment = 2

# ID ##########################################################################

def get_alert_id(alert_id: int, **kwargs) -> str:
    """Generate the alert id."""
    __alert_id = 'EVASION-{technique}'
    if alert_id == EvasionType.MetamorphicFactoryDeployment:
        __alert_id = __alert_id.format(technique='METAMORPHISM-FACTORY-DEPLOYMENT')
    if alert_id == EvasionType.MetamorphicMutantDeployment:
        __alert_id = __alert_id.format(technique='METAMORPHISM-MUTANT-DEPLOYMENT')
    return __alert_id

# NAME ########################################################################

def get_alert_name(alert_id: int, sender: str, recipient: str, **kwargs) -> str:
    """Generate the alert name."""
    return 'Metamorphism: {contract} contract deployment'.format(contract='factory' if alert_id == EvasionType.MetamorphicFactoryDeployment else 'mutant')

# DESCRIPTION #################################################################

def get_alert_description(alert_id: int, sender: str, recipient: str, **kwargs) -> str:
    """Generate the alert description."""
    return 'Metamorphism: {sender} is deploying a {contract} contract at {recipient}'.format(
        sender=sender,
        recipient=recipient,
        contract='factory' if alert_id == EvasionType.MetamorphicFactoryDeployment else 'mutant')

# TAXONOMY ####################################################################

def get_alert_type(**kwargs) -> str:
    """Generate the alert type."""
    return forta_agent.FindingType.Suspicious

def get_alert_severity(**kwargs) -> str:
    """Generate the alert type."""
    return forta_agent.FindingSeverity.Info

# LABELS ######################################################################

def get_alert_labels(chain_id: int, alert_id: int, recipient: str, confidence: float, **kwargs) -> str:
    """Generate the alert labels."""
    __labels = []
    # factory
    if alert_id == EvasionType.MetamorphicFactoryDeployment:
        __labels.append(forta_agent.Label({
            'entityType': forta_agent.EntityType.Address,
            'label': "metamorphic-factory-contract",
            'entity': recipient,
            'confidence': round(confidence, 1),
            'metadata': {'chain_id': chain_id}}))
    # mutant
    if alert_id == EvasionType.MetamorphicMutantDeployment:
        __labels.append(forta_agent.Label({
            'entityType': forta_agent.EntityType.Address,
            'label': "metamorphic-contract",
            'entity': recipient,
            'confidence': round(confidence, 1),
            'metadata': {'chain_id': chain_id}}))
    return __labels

# ACTUAL ######################################################################

format_finding = forta_toolkit.findings.format_finding_factory(
    get_alert_id=get_alert_id,
    get_alert_name=get_alert_name,
    get_alert_description=get_alert_description,
    get_alert_type=get_alert_type,
    get_alert_severity=get_alert_severity,
    get_alert_labels=get_alert_labels,
    get_alert_log=get_alert_description,)
