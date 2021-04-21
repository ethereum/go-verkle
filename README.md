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

|Network|Node size|Parallel?|Storage?|DB?|BLS library|Time|# accounts|#slots|
|-------|---------|---------|--------|---|-----------|----|----------|------|
|Mainnet|1024|No|No|No|Herumi|3h30m24.663s|114215117|0|
|Mainnet|1024|No|Yes|No|Herumi|16h36m7.043s|114215117|400223042|
|Mainnet|1024|Yes|Yes|No|Herumi|10h1m34.056s|114215117|400223042|
|Mainnet|1024|Yes|Yes|Yes|Herumi|12h47m22.309s|114215117|400223042|
|Mainnet|256|Yes|Yes|No|Herumi|18h45m21.182s|114215117|400223042|
|Mainnet|256|Yes|Yes|Yes|Herumi||114215117|400223042|
|Görli|1024|No|Yes|No|Herumi|~30min|1104810|35900044|

## Size measurements

Values with experimental encoding

|Network|Node size|Verkle tree size in DB|
|-------|---------|----------------------|
|Mainnet|1024|68G|
|Görli|1024|3.6G|


## Insertion/update benchmarks

|Initial tree size|Action|Width|Average time|
|-----------------|------|-----|------------|
|1M leaves|Insert 10K leaves|1024|25ms|
|1M leaves|Update 10K leaves|1024|7ms|

## Proof generation/verification benchmarks

|Initial tree size|Action|Width|Average time|
|-----------------|------|-----|------------|
|10K leaves|Proof for 1 leaf|1024|0.93s|
|10K leaves|Verify proof|1024|4ms|

