[![CircleCI](https://circleci.com/gh/gballet/go-verkle.svg?style=shield)](https://circleci.com/gh/gballet/go-verkle)

# go-verkle

A **very experimental** implementation of [Verkle trees](https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg). When production-ready, the code is to be split between go-kzg and go-ethereum.

Supported node widths are 8 and 10 bits.

### Running the tests

```
$ go test .
```

### Benchmarks

```
$ go test . -bench Bench
```

## Performance measurements

This table measures the time it takes to calculate the root commitment of the current state of an Ethereum network:

|Network|Node size|Parallel?|Storage?|BLS library|Time|# accounts|#slots|
|-------|---------|---------|--------|-----------|----|----------|------|
|Mainnet|1024|No|No|Herumi|3h30m24.663s|114215117|0|
|Mainnet|1024|No|Yes|Herumi||114215117|400223042|
|Mainnet|1024|Yes|Yes|Herumi|10h1m34.056s|114215117|400223042|
|Mainnet|256|No|No|Herumi||114215117|0|
|Mainnet|256|No|No|Herumi||114215117|400223042|
|Goerli|1024|No|No|Herumi|~30min|1104810|35900044|
