package messagetrace

import (
	"context"
	"encoding/json"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func getJSON(ctx context.Context, backend store.Store, key string, value any) error {
	data, err := backend.Get(ctx, model.NSMessageTrace, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func marshal(value any) ([]byte, error) { return json.Marshal(value) }

func unmarshal(data []byte, value any) error { return json.Unmarshal(data, value) }
