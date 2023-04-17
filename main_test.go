package main

import (
	"testing"
)

func benchmarkFact(b *testing.B) {
	for x := 0; x < b.N; x++ {
		main()
	}
}

func BenchmarkFact20(b *testing.B) {
	benchmarkFact(b)
}
