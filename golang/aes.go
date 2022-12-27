package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func _readFile(filename string) string {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	if len(content) == 0 {
		panic("Please check content in " + filename)
	}
	return string(content)
}

func _getSha256Encrypt(secret string) []byte {
	h := sha256.New()
	h.Write([]byte(secret))
	return h.Sum(nil)
}

func _pad(unpaddedText string) []byte {
	numberOfBytesToPad := aes.BlockSize - len(unpaddedText)%aes.BlockSize
	paddedText := make([]byte, len(unpaddedText)+numberOfBytesToPad)
	copy(paddedText[:len(unpaddedText)], unpaddedText)
	copy(paddedText[len(unpaddedText):], bytes.Repeat([]byte{byte(rune(numberOfBytesToPad))}, numberOfBytesToPad))
	return paddedText
}

func _unpad(paddedText []byte) []byte {
	paddingLength := int(paddedText[len(paddedText)-1])
	return paddedText[:len(paddedText)-paddingLength]
}

func encrypt(secret string, rawText string) {
	key := _getSha256Encrypt(secret)
	paddedText := _pad(rawText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(paddedText))
	_, err = rand.Read(ciphertext)
	if err != nil {
		panic(err)
	}
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	fmt.Printf("%x\n", ciphertext)
}

func decrypt(secret string, encryptedTxt string) {
	key := _getSha256Encrypt(secret)
	ciphertext, _ := hex.DecodeString(encryptedTxt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	paddedText := make([]byte, len(ciphertext))
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(paddedText, ciphertext)

	fmt.Printf("%s\n", _unpad(paddedText))
}

func main() {
	secret := _readFile("secret.txt")
	inputText := _readFile("input.txt")
	if len(os.Args) == 2 && os.Args[1] == "encrypt" {
		encrypt(secret, inputText)
	} else if len(os.Args) == 2 && os.Args[1] == "decrypt" {
		decrypt(secret, inputText)
	} else {
		fmt.Println("Invalid Argument.")
	}
}
