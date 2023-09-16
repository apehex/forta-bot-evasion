"""Indicators on token contracts."""

import functools

import src.indicators.generic
import src.parsing.bytecode
import src.parsing.inputs

# CONSTANTS ###################################################################

INTERFACES = {
    'erc-20': (
        # totalSupply()
        '18160ddd',
        # balanceOf(address)
        '70a08231',
        # transfer(address,uint256)
        'a9059cbb',
        # allowance(address,address)
        'dd62ed3e',
        # approve(address,uint256)
        '095ea7b3',
        # transferFrom(address,address,uint256)
        '23b872dd'),
    'erc-721': (
        # balanceOf(address)
        '70a08231',
        # ownerOf(uint256)
        '6352211e',
        # safeTransferFrom(address,address,uint256,bytes)
        'b88d4fde',
        # safeTransferFrom(address,address,uint256)
        '42842e0e',
        # transferFrom(address,address,uint256)
        '23b872dd',
        # approve(address,uint256)
        '095ea7b3',
        # setApprovalForAll(address,bool)
        'a22cb465',
        # getApproved(uint256)
        '081812fc',
        # isApprovedForAll(address,address)
        'e985e9c5'),
    'erc-777': (
        # name()
        '06fdde03',
        # symbol()
        '95d89b41',
        # granularity()
        '556f0dc7',
        # totalSupply()
        '18160ddd',
        # balanceOf(address)
        '70a08231',
        # send(address,uint256,bytes)
        '9bd9bbc6',
        # burn(uint256,bytes)
        'fe9d9303',
        # isOperatorFor(address,address)
        'd95b6371',
        # authorizeOperator(address)
        '959b8c3f',
        # revokeOperator(address)
        'fad8b32a',
        # defaultOperators()
        '06e48538',
        # operatorSend(address,address,uint256,bytes,bytes)
        '62ad1b83',
        # operatorBurn(address,uint256,bytes,bytes)
        'fc673c4f'),
    'erc-1155': (
        # balanceOf(address,uint256)
        '00fdd58e',
        # balanceOfBatch(address[],uint256[])
        '4e1273f4',
        # setApprovalForAll(address,bool)
        'a22cb465',
        # isApprovedForAll(address,address)
        'e985e9c5',
        # safeTransferFrom(address,address,uint256,uint256,bytes)
        'f242432a',
        # safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
        '2eb2c2d6'),}

# ERC-20 ######################################################################

@functools.lru_cache(maxsize=128)
def bytecode_has_erc20_interface(bytecode: str, interface: tuple=INTERFACES['erc-20'], threshold: float=0.8) -> bool:
    return src.indicators.generic.bytecode_implements_interface(bytecode=bytecode, interface=interface, threshold=threshold)

# ERC-721 #####################################################################

@functools.lru_cache(maxsize=128)
def bytecode_has_erc721_interface(bytecode: str, interface: tuple=INTERFACES['erc-721'], threshold: float=0.8) -> bool:
    return src.indicators.generic.bytecode_implements_interface(bytecode=bytecode, interface=interface, threshold=threshold)

# ERC-777 #####################################################################

@functools.lru_cache(maxsize=128)
def bytecode_has_erc777_interface(bytecode: str, interface: tuple=INTERFACES['erc-777'], threshold: float=0.8) -> bool:
    return src.indicators.generic.bytecode_implements_interface(bytecode=bytecode, interface=interface, threshold=threshold)

# ERC-1155 ####################################################################

@functools.lru_cache(maxsize=128)
def bytecode_has_erc1155_interface(bytecode: str, interface: tuple=INTERFACES['erc-1155'], threshold: float=0.8) -> bool:
    return src.indicators.generic.bytecode_implements_interface(bytecode=bytecode, interface=interface, threshold=threshold)

# ANY TOKEN ###################################################################

@functools.lru_cache(maxsize=128)
def bytecode_has_any_token_interface(bytecode: str, threshold: float=0.8) -> bool:
    return (
        bytecode_has_erc20_interface(bytecode=bytecode, threshold=threshold)
        or bytecode_has_erc721_interface(bytecode=bytecode, threshold=threshold)
        or bytecode_has_erc777_interface(bytecode=bytecode, threshold=threshold)
        or bytecode_has_erc1155_interface(bytecode=bytecode, threshold=threshold))
