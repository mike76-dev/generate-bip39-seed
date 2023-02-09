package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
)

var numWords *int

func bip39checksum(entropy []byte) uint64 {
	hash := sha256.Sum256(entropy[:])
	var result uint64
	if *numWords == 12 {
		result = uint64((hash[0] & 0xF0) >> 4)
	} else {
		result = uint64(hash[0])
	}
	return result
}

func encodeBIP39Phrase(entropy []byte) string {
	// Convert entropy to a 128- or 256-bit integer.
	ints := make([]uint64, 4)
	ints[0] = binary.BigEndian.Uint64(entropy[:8])
	ints[1] = binary.BigEndian.Uint64(entropy[8:16])
	if *numWords == 24 {
		ints[2] = binary.BigEndian.Uint64(entropy[16:24])
		ints[3] = binary.BigEndian.Uint64(entropy[24:])
	}

	// Convert each group of 11 bits into a word.
	words := make([]string, *numWords)
	// Last word is special: 4 or 8 bits are checksum.
	var w uint64
	if *numWords == 12 {
		w = ((ints[1] & 0x7F) << 4) | bip39checksum(entropy)
		ints[3] = ints[1] >> 7 | ints[0] << (64 - 7)
		ints[2] = ints[0] >> 7
		ints[1] = 0
		ints[0] = 0
		
	} else {
		w = ((ints[3] & 0x07) << 8) | bip39checksum(entropy)
		ints[3] = ints[3] >> 3 | ints[2] << (64 - 3)
		ints[2] = ints[2] >> 3 | ints[1] << (64 - 3)
		ints[1] = ints[1] >> 3 | ints[0] << (64 - 3)
		ints[0] >>= 3
	}
	words[len(words) - 1] = bip39EnglishWordList[w]
	for i := len(words) - 2; i >= 0; i-- {
		words[i] = bip39EnglishWordList[ints[3] & 0x7FF]
		ints[3] = ints[3] >> 11 | ints[2] << (64 - 11)
		ints[2] = ints[2] >> 11 | ints[1] << (64 - 11)
		ints[1] = ints[1] >> 11 | ints[0] << (64 - 11)
		ints[0] >>= 11
	}

	return strings.Join(words, " ")
}

func newSeedPhrase() string {
	entropy := make([]byte, 32 * (*numWords) / 24)
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("insufficient system entropy")
	}
	return encodeBIP39Phrase(entropy)
}

func main() {
	numWords = flag.Int("words", 12, "number of words in the seed")
	flag.Parse()
	if *numWords != 12 && *numWords != 24 {
		fmt.Println("ERROR: only 12- and 24-word seeds are supported")
		os.Exit(1)
	}

	fmt.Println(newSeedPhrase())
}
