"""Indicators on proxy contracts."""

import functools
import web3

import src.parsing.bytecode

# CONSTANTS ###################################################################

DELEGATE_OPCODES = ('DELEGATECALL',)

LOGIC_SLOTS = {
    # bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    'erc-1967': '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    # keccak256("org.zeppelinos.proxy.implementation")
    'zeppelinos': '7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3',
    # keccak256("PROXIABLE")
    'erc-1822': 'c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7',}

BEACON_SLOTS = {
    # bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
    'erc-1967': 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',}

INTERFACES = {
    'erc-1167': (
        # bytes4(keccak256("implementation()"))
        '5c60da1b',
        # bytes4(keccak256("childImplementation()"))
        'da525716',),
    'erc-1167': (
        # bytes4(keccak256("implementation()"))
        '5c60da1b',),
    'gnosis-safe': (
        # Gnosis Safe: bytes4(keccak256("masterCopy()"))
        'a619486e',),
    'comptroller': (
        # Comptroller: bytes4(keccak256("comptrollerImplementation()"))
        'bb82aa5e',),}

# PROXY #######################################################################

#TODO improve bytecode disassembly: wrong opcode
#TODO delegatecall opcode appears after disassembly when it's not used in original sources...

@functools.lru_cache(maxsize=128)
def bytecode_redirects_execution(bytecode: str, opcodes: tuple=DELEGATE_OPCODES) -> bool:
    return any(_o in bytecode for _o in opcodes)

# STANDARDS ###################################################################

@functools.lru_cache(maxsize=128)
def bytecode_uses_standard_proxy_slots(bytecode: str, standards: dict=LOGIC_SLOTS) -> bool:
    return any(_slot in bytecode for _slot in standards.values())

@functools.lru_cache(maxsize=128)
def bytecode_has_proxy_slots_from_several_standards(bytecode: str, standards: dict=LOGIC_SLOTS) -> bool:
    return sum(_slot in bytecode for _slot in standards.values()) > 1

# LOGIC CONTRACT ##############################################################

@functools.lru_cache(maxsize=128)
def storage_logic_addresses(w3: web3.Web3, address: str, bytecode: str, standards: dict=LOGIC_SLOTS) -> bool:
    _slots = src.parsing.bytecode.get_storage_slots(bytecode=bytecode)
    _values = (w3.eth.get_storage_at(address, _s) for _s in standards.values() if _s in _slots)
    return ('0x' + (_v.hex())[26:] for _v in _values if int(_v.hex(), 16) > 0)
