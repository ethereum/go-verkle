module github.com/gballet/go-verkle

go 1.18

require github.com/crate-crypto/go-ipa v0.0.0-20221110230207-a6614766d44b

require golang.org/x/sys v0.0.0-20220919091848-fb04ddd9f9c8 // indirect

// Temp replace to see the results of https://github.com/crate-crypto/go-ipa/pull/30
replace github.com/crate-crypto/go-ipa => github.com/jsign/go-ipa v0.0.0-20221111003617-c4287fc0c04e
