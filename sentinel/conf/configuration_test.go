package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfiguration(t *testing.T) {
	t.Setenv("PROVIDER_HUB_URI", "http://127.0.0.1:1317")
	t.Setenv("MONIKER", "monkey")
	t.Setenv("WEBSITE", "webby")
	t.Setenv("DESCRIPTION", "dezy")
	t.Setenv("LOCATION", "locy")
	t.Setenv("PORT", "4000")
	t.Setenv("SOURCE_CHAIN", "sourcey")
	t.Setenv("EVENT_STREAM_HOST", "hosty")
	t.Setenv("PROVIDER_PUBKEY", "cosmospub1addwnpepqg3523h7e7ggeh6na2lsde6s394tqxnvufsz0urld6zwl8687ue9c3dasgu")
	t.Setenv("FREE_RATE_LIMIT", "99")
	t.Setenv("CLAIM_STORE_LOCATION", "clammy")
	t.Setenv("CONTRACT_CONFIG_STORE_LOCATION", "configy")
	t.Setenv("PROVIDER_CONFIG_STORE_LOCATION", "providy")

	config := NewConfiguration()

	require.Equal(t, config.Moniker, "monkey")
	require.Equal(t, config.Website, "webby")
	require.Equal(t, config.Location, "locy")
	require.Equal(t, config.Port, "4000")
	require.Equal(t, config.SourceChain, "sourcey")
	require.Equal(t, config.EventStreamHost, "hosty")
	require.Equal(t, config.ProviderPubKey.String(), "cosmospub1addwnpepqg3523h7e7ggeh6na2lsde6s394tqxnvufsz0urld6zwl8687ue9c3dasgu")
	require.Equal(t, config.FreeTierRateLimit, 99)
	require.Equal(t, config.ClaimStoreLocation, "clammy")
	require.Equal(t, config.ContractConfigStoreLocation, "configy")
	require.Equal(t, config.ProviderConfigStoreLocation, "providy")
}
