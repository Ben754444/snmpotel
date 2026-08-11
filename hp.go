package main

import (
	"log/slog"
	"strings"
)

// only tested on aruba, TODO test on the comwares

type HPLogFields struct {
	severity slog.Level
	date     string
	time     string
	id       string
	module   string
	message  string
}

var severityMap = map[string]slog.Level{
	"D": slog.LevelDebug,
	"I": slog.LevelInfo,
	"W": slog.LevelWarn,
	"E": slog.LevelError,
	"F": slog.Level(12), // idk if this will work
}

func extractHPLogFields(desc string) HPLogFields {
	severity := desc[0:1]
	date := desc[2:10]
	time := desc[11:19]
	id := desc[20:25]
	text := strings.SplitN(desc[25:], ":", 2)

	return HPLogFields{
		severity: severityMap[severity],
		date:     date,
		time:     time,
		id:       id,
		module:   strings.TrimSpace(text[0]),
		message:  strings.TrimSpace(text[1]),
	}
}
