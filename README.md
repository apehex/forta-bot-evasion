# Detecting Evasion Techniques

## Description

Implementation for the detection techniques described in the [report about smart contract evasion techniques][report-web3-evasion] by the [Apehex][github-apehex].

Here, "evasion" refers to any tactic that deceives end-users or circumvents defense mechanisms.

## Support

The bots use the transaction traces, so they only runs on Ethereum for now.

## Table of Contents

- [Metamorphic Contracts](#metamorphic-contracts)
- [Red Pill Contracts](#red-pill-contracts)
- [Scoring The Transactions](#scoring-the-ransactions)
- [Options](#options)
- [Development](#development)
  - [Changelog](#changelog)
  - [Todo](#todo)
  - [Performances](#performances)
- [Credits](#credits)
- [License](#license)

## Metamorphic Contracts

Metamorphic contracts have the ability to change their bytecode while keeping their address.
They leverage the opcode `CREATE2` in a factory contract to control the deployment address of a "mutant" contract.

### Examples

Metamorphism has been used by MEV bots and hackers.
This technique requires 2 intermediate contracts, the factory and implementation contracts, to (re)deploy the mutant contract.

Factory deployment:

- Tornado hack: [0x3e93ee75ffeb019f1d841b84695538571946fd9477dcd3ecf0790851f48fbd1a](https://explorer.phalcon.xyz/tx/eth/0x3e93ee75ffeb019f1d841b84695538571946fd9477dcd3ecf0790851f48fbd1a)
- 0age demo: [0x0f7c1dad199b29bc016c0984194b7b29ba68b130bd3d9a83e5bb20de7159d33c](https://explorer.phalcon.xyz/tx/eth/0x0f7c1dad199b29bc016c0984194b7b29ba68b130bd3d9a83e5bb20de7159d33c)
- MEV bot: [0x29b2d5787757d494907b349662a3730340c88641d5ae78037928c2870d2b4cce](https://explorer.phalcon.xyz/tx/eth/0x29b2d5787757d494907b349662a3730340c88641d5ae78037928c2870d2b4cce)

Implementation + mutant creation:

- Tornado hack: [0x3e93ee75ffeb019f1d841b84695538571946fd9477dcd3ecf0790851f48fbd1a](https://explorer.phalcon.xyz/tx/eth/0x3e93ee75ffeb019f1d841b84695538571946fd9477dcd3ecf0790851f48fbd1a)
- 0age demo: [0x7bff38c773d511cb00b9addef32b4703c69d46a3470eb0f8257b65470067a5d4](https://explorer.phalcon.xyz/tx/eth/0x7bff38c773d511cb00b9addef32b4703c69d46a3470eb0f8257b65470067a5d4)
- MEV bot: [0x3bfcc1c5838ee17eec1ddda2f1ff0ac1c1ccdbd30dd520ee41215c54227a847f](https://explorer.phalcon.xyz/tx/eth/0x3bfcc1c5838ee17eec1ddda2f1ff0ac1c1ccdbd30dd520ee41215c54227a847f)

Mutant destruction:

- MEV bot: [0xff7c1a73c054b75f146afe109972a608afd9503b6962e062c392e131b1678b89](https://explorer.phalcon.xyz/tx/eth/0xff7c1a73c054b75f146afe109972a608afd9503b6962e062c392e131b1678b89)

### Alerts

The metamorphic contracts are spotted when created to perform static analysis on the bytecode:

- `METAMORPHISM-FACTORY-DEPLOYMENT`:
    - the factory address is attached as a label
- `METAMORPHISM-MUTANT-DEPLOYMENT`:
    - the mutant address is attached as a label

For all the alerts:

- Type is always set to `Suspicious`
- Severity is always `Info`
- Metadata:
  - `confidence`: the estimated probability of a given detection
  - `chain_id`: the chain id
  - `from`: the transaction sender
  - `to`: the transaction recipient
  - `anomaly_score`: the alert rate for this combination of bot / alert type

### Detection Process

Out of all the transactions on the target contracts, the factory creation and the mutant creation are the most outstanding.

The factory is detected by static analysis on its bytecode.
And the mutant contract is detected by identifying specific "metamorphic init code" and comparing its creation code to its runtime code.

|Factory detection | Mutant detection |
| ---------------- | ---------------- |
|![Metamorphism: factory detection][image-metamorphism-factory-detection]|![Metamorphism: factory detection][image-metamorphism-mutant-detection]|

In both cases, one of the main indicator is finding "metamorphic init code".
This init code is a stager that is required to leverage the `CREATE2`, it looks like this:

```
5860208158601c335a63aaf10f428752fa158151803b80938091923cf3
```

### Indicators

#### Metamorphic Factory

- runtime bytecode contains OPCODE `CREATE`
- runtime bytecode contains OPCODE `CREATE2`
- creation bytecode contains metamorphic init code

#### Mutant Contract

- creation bytecode is metamorphic init code
- runtime bytecode is not included in creation bytecode
- runtime bytecode has changed

## Red Pill Contract

Red-pill contracts try to detect simulation environments by looking for default values in the global variables.

They perform innocuous actions during simulation and activate the malicious functions only on the mainnet.

### Examples

Boiled to the essential, a red-pill contract looks like:

```solidity
contract RedPill {
    function print() public view returns (string memory) {
        if (block.coinbase == address(0x0000000000000000000000000000000000000000)) {
            return "blue pill";
        } else {
            return "red pill";
        }
    }
}
```

### Alerts

The red-pill contracts are spotted when created to perform static analysis on the bytecode:

- `LOGIC-BOMB-RED-PILL-DEPLOYMENT`:
    - the address of the contract is attached as a label

For all the alerts:

- Type is always set to `Suspicious`
- Severity is always `Info`
- Metadata:
  - `confidence`: the estimated probability of a given detection
  - `chain_id`: the chain id
  - `from`: the transaction sender
  - `to`: the transaction recipient
  - `anomaly_score`: the alert rate for this combination of bot / alert type

### Detection Process

The detection looks for conditional branches depending on the global variables.
These tests have a pattern that can be directly found in the bytecode with regex.

It matches chunks of HEX encoded bytecode like:

```
600073ffffffffffffffffffffffffffffffffffffffff164173ffffffffffffffffffffffffffffffffffffffff16141561012757
```

```
6000                                          # PUSH1 0
73ffffffffffffffffffffffffffffffffffffffff16  # cast to address
41                                            # block.coinbase
73ffffffffffffffffffffffffffffffffffffffff16  # cast to address
1415                                          # equality test
610127                                        # PUSH2 => instruction offset
57                                            # JUMPI
```

The detection regex accounts for variation in the compilation process due to solidity version and optimization parameters.

### Indicators

- bytecode contains a comparison between `COINBASE` and `address(0x0000000000000000000000000000000000000000)`
- bytecode contains a comparison between `PREVRANDAO` and `0`

Note: depending on the EVM version the opcode `0x44` is called `DIFFICULTY` or `PREVRANDAO`.

## Scoring The Transactions

The bot decisions are guided by probability metrics / scores.

### Interpretation Of Probabilities

The confidence that a transaction match a given target is a ratio that can be interpreted as follows:

- if equal to `0.5`, it is undecided, the bot didn't find enough evidence for / against
- from `0.5` to `1`, the chances go toward the certainty of a match
- from `0.5` to `0`, the agent is ruling out the possibility of a match

### Scoring Process

These metrics are computed in two steps:

- first all the indicators (IOCs) are computed
- then each indicator is quantified
- then these individual indicators are combined into a probability

The indicators for each evasion technique are listed in the previous sections.

### Quantifying The Indicators

The indicators are boolean values that signal the presence / absence of a given feature in the transaction.
`True` and `False` values are quantified by their impact on the score:

- `0.5` when the indicator has no impact
- `0.5` to `1` the more it increases the probability of a match
- `0.5` to `0` the more it lessens the probability of a match

### Combining Probabilities

Finally, the list of quantified indicators is turned into probabilities with the conflation function, $\xi$:

$$\begin{align}
Conflation(p_1, ..., p_N) &= \xi(p_1, ..., p_N) \\
                          &= \frac{{\prod_{i=1}}^{N} p_i}{{\prod_{i=1}}^{N} p_i + {\prod_{i=1}}^{N} (1 - p_i)}
\end{align}$$

Given a list of probabilities $\{p_i\}$ and an extra probability $p$, the conflation has the following properties:

- if $p = 0.5$ then $\xi(p_1, ..., p_N, p) = \xi(p_1, ..., p_N)$
- if $p > 0.5$ then $\xi(p_1, ..., p_N, p) > \xi(p_1, ..., p_N)$
- if $p < 0.5$ then $\xi(p_1, ..., p_N, p) < \xi(p_1, ..., p_N)$

For example:

- when an indicator (presence / absence) doesn't add information it can be scored as `0.5`.
- `0.9` to greatly increase the probability
- `0.4` to slightly decrease the probability
- `0.1` to strongly decrease the probability
- etc

Rather than each individual score, it is the tendency of the list of scores that drives the overall metric toward a low / high probability.

## Options

The bot settings are located in `src/options.py`:

```python
MIN_CONFIDENCE = 0.7 # probability threshold
ALERT_HISTORY_SIZE = 16384 # in number of transactions recorded
```

The bot only fires alerts when the probability score for a given threat is above `MIN_CONFIDENCE`.

It keeps a local history of all the alerts raised to compute stats.
The history size is set by `ALERT_HISTORY_SIZE`.

## Tests

The bots use the libraries [`toolblocks`][github-apehex-toolbox] and [`ioseeth`][github-apehex-ioseeth], which come with extensive unit tests.

They can be run in the root directory of each of these packages with `python -m pytest`.

## Development

Contributions welcome!

### Changelog

See [CHANGELOG](.github/CHANGELOG.md).

### TODO

See [TODO](.github/TODO.md).

### Performances

The web requests are cached.

Bytecode queries and balance checks require time and are performed only when relevant.

## Credits

Original work by [apehex](https://github.com/apehex).

Relies on the packages:

- [`ioseeth`][github-apehex-ioseeth] for the detection logic
- [`toolblocks`][github-apehex-toolbox] for the data wrangling

## License

See [LICENSE.md](LICENSE.md).

[github-apehex]: https://github.com/apehex/
[github-apehex-ioseeth]: https://github.com/apehex/web3-threat-indicators
[github-apehex-toolbox]: https://github.com/apehex/web3-toolbox
[image-metamorphism-factory-detection]: .github/images/metamorphism-factory-detection.png
[image-metamorphism-mutant-detection]: .github/images/metamorphism-mutant-detection.png
[report-web3-evasion]: https://github.com/apehex/web3-evasion-techniques/blob/main/report/web3-evasion-techniques.pdf
