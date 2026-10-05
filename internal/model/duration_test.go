package model

import (
	"math"
	"testing"
	"time"
)

func TestHistoricalDurationsSaturateWithoutBecomingPermanent(t *testing.T) {
	for _, value := range []int64{MaxDurationSeconds, MaxDurationSeconds + 1, math.MaxInt64} {
		if got := SafeSeconds(value); got <= 0 || got != time.Duration(MaxDurationSeconds)*time.Second {
			t.Fatalf("时长 %d 溢出: %v", value, got)
		}
	}
	if SafeHours(math.MaxInt) > 0 && SafeHours(math.MaxInt) != SafeSeconds(MaxDurationSeconds) {
		t.Fatal("小时转换未饱和")
	}
}
