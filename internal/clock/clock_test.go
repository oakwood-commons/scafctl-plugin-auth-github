package clock

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealNewTicker(t *testing.T) {
	r := Real{}
	ticker := r.NewTicker(50 * time.Millisecond)
	require.NotNil(t, ticker)
	defer ticker.Stop()

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	case <-time.After(1 * time.Second):
		t.Fatal("ticker did not fire within 1s")
	}
}

func TestRealTickerReset(t *testing.T) {
	r := Real{}
	ticker := r.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	ticker.Reset(50 * time.Millisecond)

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	case <-time.After(1 * time.Second):
		t.Fatal("ticker did not fire after reset")
	}
}

func TestMockNewTicker(t *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)
	require.NotNil(t, ticker)

	// Mock ticker channel is pre-filled, so reads should not block.
	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	default:
		t.Fatal("mock ticker channel should have data")
	}
}

func TestMockTickerStop(_ *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)
	// Stop should not panic.
	ticker.Stop()
}

func TestMockTickerReset(t *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)

	// Drain the pre-filled buffer.
	for {
		select {
		case <-ticker.C():
		default:
			goto drained
		}
	}
drained:

	// After Reset, channel should be refilled.
	ticker.Reset(time.Second)

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	default:
		t.Fatal("mock ticker channel should have data after reset")
	}
}

func TestMockTickerSend(t *testing.T) {
	m := Mock{}
	ticker := m.NewTicker(time.Second)

	// Drain the pre-filled buffer.
	for {
		select {
		case <-ticker.C():
		default:
			goto drained
		}
	}
drained:

	// Send should deliver a value.
	mt := ticker.(*mockTicker)
	mt.Send()

	select {
	case ts := <-ticker.C():
		assert.False(t, ts.IsZero())
	default:
		t.Fatal("Send should have delivered a value")
	}
}

func TestRealSleep(t *testing.T) {
	r := Real{}

	require.NoError(t, r.Sleep(context.Background(), 0))
	require.NoError(t, r.Sleep(context.Background(), 5*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := r.Sleep(ctx, time.Hour)
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
}

func TestMockSleep(t *testing.T) {
	m := Mock{}
	require.NoError(t, m.Sleep(context.Background(), 10*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, m.Sleep(ctx, 10*time.Second), context.Canceled)
}
