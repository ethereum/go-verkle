package verkle

import (
	"encoding/json"
	"testing"
)

func TestJSONDeserialization(t *testing.T) {
	str := `{                                                                                                                                                                                                                                                                                       
      "stem": "0x97233a822ee74c294ccec8e4e0c65106b374d4423d5d09236d0f6c6647e185",
      "suffixDiffs": [
        { "suffix": 0, "currentValue": null, "newValue": null },
        { "suffix": 1, "currentValue": null, "newValue": null },
        { "suffix": 2, "currentValue": null, "newValue": null },
        { "suffix": 3, "currentValue": null, "newValue": null },
        { "suffix": 4, "currentValue": null, "newValue": null }
      ]                                                                                                                                                                                                                                                                                     
    }`
	var statediff StemStateDiff
	err := json.Unmarshal([]byte(str), &statediff)
	if err != nil {
		t.Fatal(err)
	}
}
