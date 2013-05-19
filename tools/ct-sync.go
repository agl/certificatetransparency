// This utility program synchronises a file containing compressed log entries
// to disk. It will download any new log entries and check the tree hash.

package main

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agl/certificatetransparency"
)

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

func displayProgress(statusChan chan certificatetransparency.OperationStatus, wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-statusChan
		if !ok {
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case status, ok = <-statusChan:
				if !ok {
					return
				}
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			clearLine()
			fmt.Printf("%s %.1f%% (%d of %d)", symbols[symbolIndex], status.Percentage(), status.Current, status.Length)
		}
	}()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	out, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer out.Close()

	entriesFile := certificatetransparency.EntriesFile{out}
	fmt.Printf("Counting existing entries... ")
	count, err := entriesFile.Count()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to read entries file: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d\n", count)

	fmt.Printf("Fetching signed tree head... ")
	sth, err := certificatetransparency.PilotLog.GetSignedTreeHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d total entries at %s\n", sth.Size, sth.Time.Format(time.ANSIC))
	if count == sth.Size {
		fmt.Printf("Nothing to do\n")
		return
	}

	statusChan := make(chan certificatetransparency.OperationStatus, 1)
	wg := new(sync.WaitGroup)
	displayProgress(statusChan, wg)
	_, err = certificatetransparency.PilotLog.DownloadRange(out, statusChan, count, sth.Size)
	wg.Wait()

	clearLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while downloading: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Hashing tree\n")
	entriesFile.Seek(0, 0)
	statusChan = make(chan certificatetransparency.OperationStatus, 1)
	wg = new(sync.WaitGroup)
	displayProgress(statusChan, wg)
	treeHash, err := entriesFile.HashTree(statusChan, sth.Size)
	wg.Wait()

	clearLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing tree: %s\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(treeHash[:], sth.Hash) {
		fmt.Fprintf(os.Stderr, "Hashes do not match! Calculated: %x, STH contains %x\n", treeHash, sth.Hash)
		os.Exit(1)
	}
}
