[![CircleCI](https://circleci.com/gh/gballet/go-verkle.svg?style=shield)](https://circleci.com/gh/gballet/go-verkle)

# go-verkle

A **very experimental** implementation of [Verkle trees](https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg). When production-ready, the code is to be split between go-kzg and go-ethereum.

Supported node widths are 8 and 10 bits.

### Notes

 * [X] Proofs are given in pi and rho form, not sigma form
 * [X] Generated proofs are currently incorrect.
 * [X] Nodes have 1024 children. More sizes should be supported, but it hasn't been tested.

### Running the tests

```
$ go test .
```
