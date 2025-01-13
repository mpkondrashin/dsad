package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var (
	version = "1.0.0"

	banner = ` ______________________________________________________________________________
||----------------------------------------------------------------------------||
||                  Deep Security Agent Debug Anonymizer                      ||
||                              Version %6s                                ||
||       Copyright (c) 2024, Michael Kondrashin (mkondrashin@gmail.com)       ||
||                             All rights reserved.                           ||
||  This software is provided 'as is' and without any express or implied      ||
||  warranties, including, without limitation, the implied warranties of      ||
||  merchantability and fitness for a particular purpose. In no event shall   ||
||  the author be liable for any damages whatsoever, including, without       ||
||  limitation, damages for loss of profits, business interruption, or any    ||
||  other commercial damages or losses.                                       ||
||  For more information, please visit https://github.com/mpkondrashin/dsad") ||
||  This software is distributed without any warranty.                        ||
||  By using this software, you are agreeing to the terms of this license.    ||
||____________________________________________________________________________||
 ------------------------------------------------------------------------------
`
)

const SQLitePrefix = "SQLite format "

type Anonymizer interface {
	FilterFilenames(dst io.Writer, src io.Reader) error
}

var random = rand.New(rand.NewSource(9))

type List []string

func (s *List) String() string {
	return strings.Join(*s, ",")
}

func (s *List) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	fmt.Printf(banner, version)

	var debugFilePath string
	flag.StringVar(&debugFilePath, "i", "", "File path to debug file")
	var hostnamesList List
	flag.Var(&hostnamesList, "h", "Hostnames to anonymize (Can be used multiple times)")
	var domainsList List
	flag.Var(&domainsList, "d", "Domains to anonymize (Can be used multiple times)")
	var codeword string
	flag.StringVar(&codeword, "c", "", "Codeword")
	flag.Parse()

	if debugFilePath == "" || codeword == "" {
		flag.Usage()
		return
	}

	fmt.Printf("Hostnames list: %v\n", strings.Join(hostnamesList, ", "))
	fmt.Println("Processing the debug file...")
	anonymizer := NewAnonymizerCodeword(codeword)
	for _, hostname := range hostnamesList {
		anonymizer.AddHostname(hostname)
	}
	for _, domain := range domainsList {
		anonymizer.AddDomain(domain)
	}
	statistics := NewStatistics()
	for _, h := range hostnamesList {
		statistics.Set(h, "", 0)
	}
	anonymizer.SetStatistics(statistics)

	outputFilePath := OutputFilename(debugFilePath, "_anonymized")

	err := FilterZip(anonymizer, debugFilePath, outputFilePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Done!")
	fmt.Println("Substitutions made:")
	fmt.Print(statistics)
	fmt.Printf("Output file: %s\n", outputFilePath)
}

func FilterZip(anonymizer Anonymizer, inputFilename, outputFilename string) error {
	inputZip, err := zip.OpenReader(inputFilename)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer inputZip.Close()

	outputZip, err := os.Create(outputFilename)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer outputZip.Close()

	zipWriter := zip.NewWriter(outputZip)
	defer zipWriter.Close()

	for _, file := range inputZip.File {
		srcFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file from zip: %w", err)
		}
		dstFile, err := zipWriter.Create(file.Name)
		if err != nil {
			return fmt.Errorf("failed to create file in zip: %w", err)
		}
		err = anonymizer.FilterFilenames(dstFile, srcFile)
		if err != nil {
			return fmt.Errorf("failed to anonymize %s: %w", file.Name, err)
		}
		srcFile.Close()
	}
	return nil
}

func OutputFilename(filename, suffix string) string {
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)
	ext := filepath.Ext(filename)
	name := strings.TrimSuffix(base, ext)
	newFileName := name + suffix + ext
	return filepath.Join(dir, newFileName)
}
