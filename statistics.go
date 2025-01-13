package main

import (
	"fmt"
	"strings"
)

type SData struct {
	name  string
	value int
}

type Statistics struct {
	data map[string]SData
}

func NewStatistics() *Statistics {
	return &Statistics{
		data: make(map[string]SData),
	}
}

func (s *Statistics) Add(a, b string) {
	d, ok := s.data[a]
	if ok {
		d.value++
		d.name = b
		s.data[a] = d

		return
	}
	s.data[a] = SData{b, 1}
}

func (s *Statistics) Set(a, b string, value int) {
	s.data[a] = SData{b, value}
}

func (s *Statistics) String() string {
	a := 0
	b := 0
	for key, value := range s.data {
		if len(key) > a {
			a = len(key)
		}
		if len(value.name) > b {
			b = len(value.name)
		}
	}
	var sb strings.Builder
	for key, data := range s.data {
		sb.WriteString(fmt.Sprintf("%-*s -> %-*s (%d %s)\n", a, key, b, data.name, data.value, PluralTime(data.value)))
	}
	return sb.String()
}

func PluralTime(x int) string {
	if x == 1 {
		return "time"
	}
	return "times"
}
