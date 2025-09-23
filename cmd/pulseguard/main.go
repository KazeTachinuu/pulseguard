package main

import (
	"log"

	"pulseguard/core/tui"
)

func main() {
	if err := tui.Run(); err != nil {
		log.Fatalf("tui: %v", err)
	}
}
