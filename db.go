package certificatetransparency

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// An EntriesFile represents a file containing compressed log entries.
type EntriesFile struct {
	*os.File
}

// Count returns the number of entries from the current position till the end
// of the file. On return the file will be positioned at the end.
func (f EntriesFile) Count() (count uint64, err error) {
	for {
		var zLen uint32
		if err := binary.Read(f.File, binary.LittleEndian, &zLen); err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}

		if _, err = f.Seek(int64(zLen), 1); err != nil {
			return 0, err
		}

		count++
	}

	return
}

func (f EntriesFile) readEntries(entries chan<- EntryAndPosition) error {
	defer close(entries)
	var offset int64

	index := uint64(0)
	for {
		var zLen uint32
		if err := binary.Read(f, binary.LittleEndian, &zLen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		data := make([]byte, zLen)
		if _, err := io.ReadFull(f, data); err != nil {
			return err
		}

		entries <- EntryAndPosition{
			Index:  index,
			Offset: offset,
			Length: 4 + int(zLen),
			Raw:    data,
		}

		offset += 4 + int64(zLen)
		index++
	}

	return nil
}

func mapWorker(f func(*EntryAndPosition, error), entries <-chan EntryAndPosition, wg *sync.WaitGroup) {
	defer wg.Done()

	for ent := range entries {
		err := ent.Parse()
		f(&ent, err)
	}
}

// Map runs mapFunc (possibly concurrently) on each entry in f. The entries may
// not be processed in order. Each entry is represented with an
// EntryAndPosition and, optionally, a parse error. If a parse error is
// provided, the Entry member of the EntryAndPosition will be nil.
func (f EntriesFile) Map(mapFunc func(*EntryAndPosition, error)) error {
	wg := new(sync.WaitGroup)
	entries := make(chan EntryAndPosition)

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go mapWorker(mapFunc, entries, wg)
	}

	err := f.readEntries(entries)
	wg.Wait()

	return err
}

type hashWorkersState struct {
	hashesChan chan [32]byte
	lastOffset int64
	cond       *sync.Cond
}

var (
	exteriorNodePrefix = []byte{0}
	interiorNodePrefix = []byte{1}
)

func hashTree(output *[sha256.Size]byte, h hash.Hash, hashes <-chan [sha256.Size]byte, size uint64) {
	if size == 1 {
		*output = <-hashes
		return
	}

	n := uint64(1)
	for n < size {
		n <<= 1
	}
	n >>= 1

	var left [sha256.Size]byte
	hashTree(&left, h, hashes, n)
	hashTree(output, h, hashes, size-n)
	h.Reset()
	h.Write(interiorNodePrefix)
	h.Write(left[:])
	h.Write(output[:])
	h.Sum(output[:0])
}

func hashWorker(state *hashWorkersState, entries <-chan EntryAndPosition, status chan<- OperationStatus, phase, divisor, total uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	h := sha256.New()
	var digest [sha256.Size]byte

	count := uint64(0)
	for ent := range entries {
		z := flate.NewReader(bytes.NewBuffer(ent.Raw))
		leafInput, err := readLengthPrefixed(z)
		if err != nil {
			panic(err)
		}
		z.Close()

		h.Reset()
		h.Write(exteriorNodePrefix)
		h.Write(leafInput)
		h.Sum(digest[:0])

		state.cond.L.Lock()
		for {
			if state.lastOffset == ent.Offset {
				state.hashesChan <- digest
				state.lastOffset = ent.Offset + int64(ent.Length)
				state.cond.Broadcast()
				break
			}
			state.cond.Wait()
		}
		state.cond.L.Unlock()

		if status != nil && count%divisor == phase {
			status <- OperationStatus{0, ent.Index, total}
		}
		count++
	}
}

// HashTree hashes count log entries from f and returns the tree hash. If
// status is non-nil then periodic status updates will be written to it.
func (f EntriesFile) HashTree(status chan<- OperationStatus, count uint64) (output [sha256.Size]byte, err error) {
	wg := new(sync.WaitGroup)
	entries := make(chan EntryAndPosition)

	mutex := new(sync.Mutex)
	state := &hashWorkersState{
		hashesChan: make(chan [32]byte, runtime.NumCPU()),
		cond:       sync.NewCond(mutex),
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		const statusFraction = 1000
		go hashWorker(state, entries, status, uint64(i)*statusFraction, uint64(runtime.NumCPU())*statusFraction, count, wg)
	}

	wg.Add(1)
	go func() {
		hashTree(&output, sha256.New(), state.hashesChan, count)
		wg.Done()
	}()

	if err = f.readEntries(entries); err != nil {
		return
	}
	wg.Wait()

	if status != nil {
		close(status)
	}

	return
}

// Entry represents a log entry. See
// https://tools.ietf.org/html/draft-laurie-pki-sunlight-12#section-3.1
type Entry struct {
	// Timestamp is the raw time value from the log.
	Timestamp uint64
	// Time is Timestamp converted to a time.Time
	Time              time.Time
	Type              LogEntryType
	X509Cert          []byte
	PreCertIssuerHash []byte
	TBSCert           []byte
	ExtraCerts        [][]byte

	LeafInput []byte
	ExtraData []byte
}

// EntryAndPosition represents a single entry in an entries file.
type EntryAndPosition struct {
	Index uint64
	// Offset contains the byte offset from the beginning of the file for
	// this entry.
	Offset int64
	// Length contains the number of bytes in this entry on disk.
	Length int
	// Raw contains the compressed contents of the entry.
	Raw []byte
	// Entry contains the parsed entry.
	Entry *Entry
}

func readLengthPrefixed(in io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(in, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(in, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func parseEntry(leafData, extraData []byte) (*Entry, error) {
	x := leafData
	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	if x[0] != logVersion {
		return nil, errors.New("ct: unknown entry version")
	}
	if x[1] != 0 {
		return nil, errors.New("ct: unknown leaf type")
	}
	x = x[2:]

	entry := new(Entry)
	if len(x) < 8 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Timestamp = binary.BigEndian.Uint64(x)
	entry.Time = time.Unix(int64(entry.Timestamp/1000), int64(entry.Timestamp%1000))
	x = x[8:]

	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Type = LogEntryType(x[1])
	x = x[2:]
	switch entry.Type {
	case X509Entry:
		if len(x) < 3 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<16 |
			int(x[1])<<8 |
			int(x[2])
		x = x[3:]
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.X509Cert = x[:l]
		x = x[l:]
	case PreCertEntry:
		if len(x) < 32 {
			return nil, errors.New("ct: truncated entry")
		}
		entry.PreCertIssuerHash = x[:32]
		x = x[32:]
		if len(x) < 2 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<8 | int(x[1])
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.TBSCert = x[:l]
	default:
		return nil, errors.New("ct: unknown entry type")
	}

	x = extraData
	if len(x) > 0 {
		// For an X509Entry, the contents are:
		//   ASN.1Cert certificate_chain<0..2^24-1>;
		// For a PreCertEntry, however, the contents are:
		// struct {
		//   ASN.1Cert pre_certificate;
		//   ASN.1Cert precertificate_chain<0..2^24-1>;
		// } PrecertChainEntry;
		if len(x) < 3 {
			return nil, errors.New("ct: extra data truncated")
		}
		l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
		x = x[3:]

		if entry.Type == PreCertEntry {
			if l > len(x) {
				return nil, errors.New("ct: extra data truncated")
			}
			entry.ExtraCerts = append(entry.ExtraCerts, x[:l])
			x = x[l:]

			if len(x) < 3 {
				return nil, errors.New("ct: extra data truncated")
			}
			l = int(x[0])<<16 | int(x[1])<<8 | int(x[2])
			x = x[3:]
		}

		if l != len(x) {
			return nil, errors.New("ct: extra data truncated")
		}

		for len(x) > 0 {
			if len(x) < 3 {
				return nil, errors.New("ct: extra data truncated")
			}
			l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
			x = x[3:]

			if l > len(x) {
				return nil, errors.New("ct: extra data truncated")
			}
			entry.ExtraCerts = append(entry.ExtraCerts, x[:l])
			x = x[l:]
		}
	}

	entry.LeafInput = leafData
	entry.ExtraData = extraData

	return entry, nil
}

func (e *EntryAndPosition) Parse() error {
	z := flate.NewReader(bytes.NewBuffer(e.Raw))
	leafInput, err := readLengthPrefixed(z)
	if err != nil {
		return err
	}
	extraData, err := readLengthPrefixed(z)
	if err != nil {
		return err
	}
	z.Close()

	e.Entry, err = parseEntry(leafInput, extraData)
	if err != nil {
		return err
	}

	return nil
}
