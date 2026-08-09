package main

import (
	"log/slog"
	"strconv"
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
	severity := desc[0]
	date := desc[2:9]
	time := desc[11:18]
	id := desc[20:24]
	text := strings.Split(desc[25:], ":")

	return HPLogFields{
		severity: severityMap[strconv.Itoa(int(severity))],
		date:     date,
		time:     time,
		id:       id,
		module:   text[0],
		message:  text[1],
	}
}
