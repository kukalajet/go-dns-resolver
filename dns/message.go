package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// DNSMessage represents a complete DNS message containing header, questions, and answer sections.
// It follows RFC 1035 specification for DNS message format and provides methods for
// encoding and decoding DNS messages over UDP transport.
type DNSMessage struct {
	Header     Header           // Header contains control information and section counts
	Questions  []Question       // Questions contains queries being asked
	Answers    []ResourceRecord // Answers contains resource records that answer the questions
	Authority  []ResourceRecord // Authority contains resource records from authoritative servers
	Additional []ResourceRecord // Additional contains supplementary resource records
}

// Header represents the DNS message header section as defined in RFC 1035.
// The header contains identification, flags, and counts for each section of the DNS message.
// All fields are stored in network byte order for transmission over UDP.
type Header struct {
	ID      uint16 // ID is a unique identifier for matching queries with responses
	Flags   uint16 // Flags contains query/response indicator, operation code, and response codes
	QDCOUNT uint16 // QDCOUNT specifies the number of entries in the question section
	ANCOUNT uint16 // ANCOUNT specifies the number of resource records in the answer section
	NSCOUNT uint16 // NSCOUNT specifies the number of name server resource records in the authority section
	ARCOUNT uint16 // ARCOUNT specifies the number of resource records in the additional section
}

// Pack serializes the Header into a byte slice using network byte order.
// The resulting 12-byte slice can be transmitted as the header portion of a DNS message.
// Returns an error if binary encoding fails.
func (h *Header) Pack() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, h)
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS header: %w", err)
	}
	return buf.Bytes(), nil
}

// Question represents a DNS question section entry that specifies what is being queried.
// Each question contains a domain name, the type of resource record requested,
// and the class (typically Internet class).
type Question struct {
	Name  string     // Name is the domain name being queried (e.g., "example.com")
	Type  RecordType // Type specifies the kind of resource record requested (A, AAAA, CNAME, etc.)
	Class uint16     // Class specifies the protocol family, usually 1 for Internet (IN)
}

// Pack serializes the Question into a byte slice suitable for DNS message transmission.
// The domain name is encoded using DNS label format, followed by the type and class
// fields in network byte order. Returns an error if domain name encoding fails.
func (q *Question) Pack() ([]byte, error) {
	buf := new(bytes.Buffer)

	encodedName, err := EncodeDomainName(q.Name)
	if err != nil {
		return nil, err
	}
	buf.Write(encodedName)

	binary.Write(buf, binary.BigEndian, q.Type)
	binary.Write(buf, binary.BigEndian, q.Class)

	return buf.Bytes(), nil
}

// UnpackHeader deserializes a DNS header from the first 12 bytes of a DNS message.
// The input data must contain at least 12 bytes representing a complete DNS header
// in network byte order. Returns an error if the data is too short or binary
// decoding fails.
func UnpackHeader(data []byte) (Header, error) {
	var header Header
	if len(data) < 12 {
		return header, fmt.Errorf("header data too short to unpack")
	}
	reader := bytes.NewReader(data[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return header, fmt.Errorf("failed to unpack DNS header: %w", err)
	}
	return header, nil
}

// EncodeDomainName converts a human-readable domain name into DNS wire format.
// The domain name is split into labels, each prefixed with its length byte,
// and terminated with a zero byte. Each label must not exceed 63 characters
// as per RFC 1035. Returns an error if any label exceeds the length limit.
//
// Example:
//
//	EncodeDomainName("example.com") returns [7]example[3]com[0]
func EncodeDomainName(domain string) ([]byte, error) {
	var buf bytes.Buffer
	segments := strings.Split(domain, ".")
	for _, segment := range segments {
		if len(segment) > 63 {
			return nil, fmt.Errorf("domain segment '%s' is longer than 63 characters", segment)
		}
		buf.WriteByte(byte(len(segment)))
		buf.WriteString(segment)
	}
	buf.WriteByte(0)
	return buf.Bytes(), nil
}

// DecodeDomainName extracts a domain name from DNS wire format starting at the given offset.
// It handles both regular labels and DNS message compression pointers (RFC 1035 section 4.1.4).
// Message compression allows domain names to reference previously appearing names to reduce
// message size. Returns the decoded domain name, the number of bytes consumed from the
// original offset, and any error encountered.
//
// The function properly handles:
//   - Regular labels with length-prefixed strings
//   - Compression pointers that reference earlier positions in the message
//   - Proper boundary checking to prevent buffer overruns
//   - Recursive decompression of nested pointers
func DecodeDomainName(fullMessage []byte, offset int) (string, int, error) {
	var labels []string
	startOffset := offset
	bytesRead := 0
	jumped := false

	for {
		if offset >= len(fullMessage) {
			return "", 0, fmt.Errorf("offset %d out of bounds", offset)
		}
		length := int(fullMessage[offset])
		offset++

		if length == 0 {
			if !jumped {
				bytesRead = offset - startOffset
			}
			break
		}

		if (length & 0xC0) == 0xC0 {
			if offset >= len(fullMessage) {
				return "", 0, fmt.Errorf("malformed pointer at offset %d", offset-1)
			}
			pointer := int(binary.BigEndian.Uint16(fullMessage[offset-1:offset+1]) & 0x3FFF)

			pointedName, _, err := DecodeDomainName(fullMessage, pointer)
			if err != nil {
				return "", 0, fmt.Errorf("failed to decode pointed name: %w", err)
			}
			labels = append(labels, pointedName)

			if !jumped {
				bytesRead = offset - startOffset + 1
				jumped = true
			}
			return strings.Join(labels, "."), bytesRead, nil
		}

		if offset+length > len(fullMessage) {
			return "", 0, fmt.Errorf("label length %d extends beyond message boundary", length)
		}
		labels = append(labels, string(fullMessage[offset:offset+length]))
		offset += length
	}

	if !jumped {
		bytesRead = offset - startOffset
	}

	return strings.Join(labels, "."), bytesRead, nil
}
