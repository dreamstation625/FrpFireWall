package model

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const MaxDurationSeconds = int64(math.MaxInt64 / int64(time.Second))

func ParseDurationSteps(s string) ([]int64, error) {
	var out []int64
	for _, tok := range strings.Split(s, ",") {
		v, err := strconv.ParseInt(strings.TrimSpace(tok), 10, 64)
		if err != nil || v < 0 || v > MaxDurationSeconds {
			return nil, fmt.Errorf("封禁时长需为 0 ~ %d 秒的整数（0 表示永久）", MaxDurationSeconds)
		}
		out = append(out, v)
	}
	return out, nil
}

// SafeSeconds 对历史配置做饱和计算，防止正数溢出后变成永久封禁。
func SafeSeconds(sec int64) time.Duration {
	if sec <= 0 {
		return 0
	}
	if sec > MaxDurationSeconds {
		sec = MaxDurationSeconds
	}
	return time.Duration(sec) * time.Second
}

func SafeHours(hours int) time.Duration {
	if hours <= 0 {
		return 0
	}
	if int64(hours) > MaxDurationSeconds/3600 {
		return SafeSeconds(MaxDurationSeconds)
	}
	return SafeSeconds(int64(hours) * 3600)
}
