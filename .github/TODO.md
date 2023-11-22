# TODO

## Packaging

[x] fix missing deps in Docker
[x] use packages:
    [x] toolkit
    [x] ioseeth
[x] tidy:
    [x] replace req.txt with pyproject.toml
    [x] move README & LICENSE
    [x] adapt Dockerfile
    [x] remove pytest.ini

## Bots

[x] metamorphic:
    [x] factory deployment
    [x] mutant deployment
    [ ] factory calls: get implementation address, set implementation bytecode
[ ] event poisoning:
    [x] iterate on all constraints
    [ ] constraints:
        [x] ERC-20
        [ ] ERC-1155
        [ ] ERC-1967

## Process

[x] analyze all the data sources in a single function
    [x] iterate over traces
    [x] iterate over event logs
    [x] score each evasion technique

## Stats

[ ] classify all the transactions => stats
    [ ] by contract type: pool, swap, token, proxy, phishing, etc etc
    [ ] by usage
