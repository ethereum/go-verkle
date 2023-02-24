// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type ipaproofMarshaller struct {
	CL              [IPA_PROOF_DEPTH]string `json:"cl"`
	CR              [IPA_PROOF_DEPTH]string `json:"cr"`
	FinalEvaluation string                  `json:"finalEvaluation"`
}

func (ipp *IPAProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ipaproofMarshaller{
		CL: [IPA_PROOF_DEPTH]string{
			hex.EncodeToString(ipp.CL[0][:]),
			hex.EncodeToString(ipp.CL[1][:]),
			hex.EncodeToString(ipp.CL[2][:]),
			hex.EncodeToString(ipp.CL[3][:]),
			hex.EncodeToString(ipp.CL[4][:]),
			hex.EncodeToString(ipp.CL[5][:]),
			hex.EncodeToString(ipp.CL[6][:]),
			hex.EncodeToString(ipp.CL[7][:]),
		},
		CR: [IPA_PROOF_DEPTH]string{
			hex.EncodeToString(ipp.CR[0][:]),
			hex.EncodeToString(ipp.CR[1][:]),
			hex.EncodeToString(ipp.CR[2][:]),
			hex.EncodeToString(ipp.CR[3][:]),
			hex.EncodeToString(ipp.CR[4][:]),
			hex.EncodeToString(ipp.CR[5][:]),
			hex.EncodeToString(ipp.CR[6][:]),
			hex.EncodeToString(ipp.CR[7][:]),
		},
		FinalEvaluation: hex.EncodeToString(ipp.FinalEvaluation[:]),
	})
}

func (ipp *IPAProof) UnmarshalJSON(data []byte) error {
	aux := &ipaproofMarshaller{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.FinalEvaluation) != 64 {
		return fmt.Errorf("invalid hex string for final evaluation: %s", aux.FinalEvaluation)
	}

	currentValueBytes, err := hex.DecodeString(aux.FinalEvaluation)
	if err != nil {
		return fmt.Errorf("error decoding hex string for current value: %v", err)
	}
	copy(ipp.FinalEvaluation[:], currentValueBytes)

	for i := range ipp.CL {
		if len(aux.CL[i]) != 64 {
			return fmt.Errorf("invalid hex string for CL[%d]: %s", i, aux.CL[i])
		}
		val, err := hex.DecodeString(aux.CL[i])
		if err != nil {
			return fmt.Errorf("error decoding hex string for CL[%d]: %s", i, aux.CL[i])
		}
		copy(ipp.CL[i][:], val)
		if len(aux.CR[i]) != 64 {
			return fmt.Errorf("invalid hex string for CR[%d]: %s", i, aux.CR[i])
		}
		val, err = hex.DecodeString(aux.CR[i])
		if err != nil {
			return fmt.Errorf("error decoding hex string for CR[%d]: %s", i, aux.CR[i])
		}
		copy(ipp.CR[i][:], val)
	}
	copy(ipp.FinalEvaluation[:], currentValueBytes)

	return nil
}

type verkleProofMarshaller struct {
	OtherStems            []string  `json:"otherStems"`
	DepthExtensionPresent string    `json:"depthExtensionPresent"`
	CommitmentsByPath     []string  `json:"commitmentsByPath"`
	D                     string    `json:"d"`
	IPAProof              *IPAProof `json:"ipa_proof"`
}

func (vp *VerkleProof) MarshalJSON() ([]byte, error) {
	aux := &verkleProofMarshaller{
		OtherStems:            make([]string, len(vp.OtherStems)),
		DepthExtensionPresent: hex.EncodeToString(vp.DepthExtensionPresent),
		CommitmentsByPath:     make([]string, len(vp.CommitmentsByPath)),
		D:                     hex.EncodeToString(vp.D[:]),
		IPAProof:              vp.IPAProof,
	}

	for i, s := range vp.OtherStems {
		aux.OtherStems[i] = hex.EncodeToString(s[:])
	}
	for i, c := range vp.CommitmentsByPath {
		aux.CommitmentsByPath[i] = hex.EncodeToString(c[:])
	}
	return json.Marshal(aux)
}

func (vp *VerkleProof) UnmarshalJSON(data []byte) error {
	var aux verkleProofMarshaller
	err := json.Unmarshal(data, &aux)
	if err != nil {
		return err
	}

	vp.DepthExtensionPresent, err = hex.DecodeString(aux.DepthExtensionPresent)
	if err != nil {
		return fmt.Errorf("error decoding hex string for depth and extension present: %v", err)
	}

	vp.CommitmentsByPath = make([][32]byte, len(aux.CommitmentsByPath))
	for i, c := range aux.CommitmentsByPath {
		val, err := hex.DecodeString(c)
		if err != nil {
			return fmt.Errorf("error decoding hex string for commitment #%d: %w", i, err)
		}
		copy(vp.CommitmentsByPath[i][:], val)
	}

	currentValueBytes, err := hex.DecodeString(aux.D)
	if err != nil {
		return fmt.Errorf("error decoding hex string for D: %w", err)
	}
	copy(vp.D[:], currentValueBytes)

	vp.OtherStems = make([][31]byte, len(aux.OtherStems))
	for i, c := range aux.OtherStems {
		val, err := hex.DecodeString(c)
		if err != nil {
			return fmt.Errorf("error decoding hex string for other stem #%d: %w", i, err)
		}
		copy(vp.OtherStems[i][:], val)
	}

	vp.IPAProof = aux.IPAProof
	return nil
}

type suffixStateDiffMarshaller struct {
	Suffix       byte   `json:"suffix"`
	CurrentValue string `json:"currentValue"`
}

func (ssd SuffixStateDiff) MarshalJSON() ([]byte, error) {
	var cvstr string
	if ssd.CurrentValue != nil {
		cvstr = hex.EncodeToString(ssd.CurrentValue[:])
	}
	return json.Marshal(&suffixStateDiffMarshaller{
		Suffix:       ssd.Suffix,
		CurrentValue: cvstr,
	})
}

func (ssd *SuffixStateDiff) UnmarshalJSON(data []byte) error {
	aux := &suffixStateDiffMarshaller{
		CurrentValue: "",
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.CurrentValue) != 64 && len(aux.CurrentValue) != 0 {
		return fmt.Errorf("invalid hex string for current value: %s", aux.CurrentValue)
	}

	*ssd = SuffixStateDiff{
		Suffix: aux.Suffix,
	}

	if len(aux.CurrentValue) != 0 {
		currentValueBytes, err := hex.DecodeString(aux.CurrentValue)
		if err != nil {
			return fmt.Errorf("error decoding hex string for current value: %v", err)
		}

		ssd.CurrentValue = &[32]byte{}
		copy(ssd.CurrentValue[:], currentValueBytes)
	}

	return nil
}
