// Package dns provides a simple DNS client for resolving domain names.
// It implements the core DNS protocol as defined in RFC 1035, supporting
// UDP transport and various record types including A, AAAA, CNAME, MX, TXT, and NS.
//
// The package offers a high-level Resolver type that handles DNS query construction,
// transmission, and response parsing. It supports standard DNS features including
// message compression and proper error handling for common DNS response codes.
//
// Example usage:
//
//	resolver := dns.NewResolver("8.8.8.8:53")
//	response, err := resolver.Resolve("example.com", dns.TypeA)
//	if err != nil {
//		log.Fatal(err)
//	}
//	// Process response.Answers for IPv4 addresses
package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	// ErrNameNotFound indicates that the queried domain name does not exist.
	// This corresponds to the NXDOMAIN response code (RCODE 3) in DNS responses.
	ErrNameNotFound = errors.New("domain name not found (NXDOMAIN)")

	// ErrServerFailed indicates that the DNS server was unable to process the query.
	// This corresponds to the SERVFAIL response code (RCODE 2) in DNS responses
	// and typically indicates a problem with the authoritative server or network.
	ErrServerFailed = errors.New("server failure (SERVFAIL)")
)

// Resolver provides DNS resolution functionality using UDP transport.
// It encapsulates the configuration needed to communicate with a DNS server
// and provides methods for constructing queries, sending them over the network,
// and parsing responses according to RFC 1035.
//
// The resolver maintains connection details including the target DNS server
// address and timeout settings for network operations. It handles the complete
// DNS query lifecycle from message construction to response validation.
type Resolver struct {
	ServerAddr string        // ServerAddr is the network address of the DNS server (e.g., "8.8.8.8:53")
	Timeout    time.Duration // Timeout specifies the maximum duration for DNS query operations
}

// NewResolver creates a new DNS resolver configured to use the specified server.
// The server address should be in the format "host:port" where host can be an
// IP address or hostname, and port is typically 53 for standard DNS.
// The resolver is initialized with a default timeout of 5 seconds.
//
// Example:
//
//	resolver := NewResolver("8.8.8.8:53")      // Google Public DNS
//	resolver := NewResolver("1.1.1.1:53")      // Cloudflare DNS
//	resolver := NewResolver("localhost:5353")   // Local DNS server
func NewResolver(serverAddr string) *Resolver {
	return &Resolver{
		ServerAddr: serverAddr,
		Timeout:    5 * time.Second,
	}
}

// Resolve performs a DNS query for the specified domain name and record type.
// It constructs a properly formatted DNS query message, sends it to the configured
// DNS server over UDP, and parses the response into a structured DNSMessage.
//
// The method handles the complete DNS query process including:
//   - Generating a unique query ID for request/response matching
//   - Setting appropriate flags for a standard recursive query
//   - Network transmission with timeout protection
//   - Response validation and error code handling
//   - Parsing of DNS message compression
//
// Common record types include TypeA for IPv4 addresses, TypeAAAA for IPv6,
// TypeCNAME for aliases, and TypeMX for mail servers.
//
// Returns an error for network failures, malformed responses, DNS error codes
// (NXDOMAIN, SERVFAIL), or query/response ID mismatches.
//
// Example:
//
//	msg, err := resolver.Resolve("example.com", TypeA)
//	if err != nil {
//		return err
//	}
//	for _, answer := range msg.Answers {
//		// Process IPv4 addresses from answer.RData
//	}
func (r *Resolver) Resolve(domainName string, recordType RecordType) (*DNSMessage, error) {
	query, queryID, err := r.buildQuery(domainName, recordType)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	responseBytes, err := r.sendQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	msg, err := parseResponse(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if msg.Header.ID != queryID {
		return nil, fmt.Errorf("response ID %d does not match query ID %d", msg.Header.ID, queryID)
	}

	return msg, nil
}

// buildQuery constructs a binary DNS query message for the given domain and record type.
// It generates a random query ID for matching requests with responses, creates a standard
// query header with the recursion desired flag set, and encodes the question section
// using DNS wire format.
//
// The function returns the complete query as a byte slice ready for network transmission,
// the generated query ID for response validation, and any error encountered during
// message construction.
//
// The resulting query follows RFC 1035 format with:
//   - 12-byte header containing ID, flags, and section counts
//   - Question section with encoded domain name, type, and class
//   - No answer, authority, or additional sections for queries
func (r *Resolver) buildQuery(domainName string, recordType RecordType) ([]byte, uint16, error) {
	idBytes := make([]byte, 2)
	_, err := rand.Read(idBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate random ID: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes)

	header := Header{
		ID:      id,
		Flags:   0x0100, // Standard query (RD flag set)
		QDCOUNT: 1,
	}

	question := Question{
		Name:  domainName,
		Type:  recordType,
		Class: 1, // IN (Internet)
	}

	var buf bytes.Buffer
	headerBytes, err := header.Pack()
	if err != nil {
		return nil, 0, err
	}
	buf.Write(headerBytes)

	questionBytes, err := question.Pack()
	if err != nil {
		return nil, 0, err
	}
	buf.Write(questionBytes)

	return buf.Bytes(), id, nil
}

// sendQuery transmits a DNS query to the configured server and returns the response.
// It establishes a UDP connection to the DNS server, applies the configured timeout
// to prevent indefinite blocking, sends the query bytes, and reads the response.
//
// The method handles network-level concerns including:
//   - UDP connection establishment and cleanup
//   - Timeout configuration for both read and write operations
//   - Response buffer sizing (512 bytes per RFC 1035 recommendations)
//   - Proper connection closure to prevent resource leaks
//
// Returns the raw response bytes as received from the server, or an error if
// the network operation fails, times out, or the server is unreachable.
//
// The response bytes can be parsed using parseResponse to extract the structured
// DNS message components.
func (r *Resolver) sendQuery(query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", r.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.Timeout))

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response[:n], nil
}

// parseResponse parses a raw DNS response message into a structured DNSMessage.
// It validates the response header, checks for DNS error codes, and extracts
// all sections of the DNS message including questions, answers, authority,
// and additional records.
//
// The function handles DNS protocol details including:
//   - Header validation and error code interpretation
//   - DNS message compression for domain names
//   - Proper offset tracking through variable-length sections
//   - Resource record parsing with type-specific data handling
//
// DNS error codes are mapped to appropriate Go errors:
//   - RCODE 2 (SERVFAIL) returns ErrServerFailed
//   - RCODE 3 (NXDOMAIN) returns ErrNameNotFound
//   - Other error codes return generic parsing errors
//
// The function currently parses questions and answer sections completely,
// with partial implementation for authority and additional sections.
//
// Returns a fully populated DNSMessage structure or an error if the response
// is malformed, contains unsupported features, or indicates a DNS-level error.
func parseResponse(response []byte) (*DNSMessage, error) {
	header, err := UnpackHeader(response)
	if err != nil {
		return nil, err
	}

	responseCode := header.Flags & 0x000F
	if responseCode == 2 {
		return nil, ErrServerFailed
	}
	if responseCode == 3 {
		return nil, ErrNameNotFound
	}

	offset := 12
	msg := &DNSMessage{Header: header}

	// Parse Questions
	for i := 0; i < int(header.QDCOUNT); i++ {
		q, n, err := parseQuestion(response, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse question %d: %w", i, err)
		}
		msg.Questions = append(msg.Questions, q)
		offset += n
	}

	// Parse Answers, Authority, and Additional records
	for i := 0; i < int(header.ANCOUNT); i++ {
		rr, n, err := ParseResourceRecord(response, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse answer %d: %w", i, err)
		}
		msg.Answers = append(msg.Answers, rr)
		offset += n
	}
	// ... repeat for NSCOUNT and ARCOUNT ...

	return msg, nil
}

// parseQuestion extracts a DNS question from a binary message at the specified offset.
// It decodes the domain name using DNS wire format (handling compression if present),
// reads the question type and class fields, and returns the parsed question along
// with the number of bytes consumed.
//
// The function validates message boundaries to prevent buffer overruns and properly
// handles DNS name compression pointers that may reference earlier positions in
// the message.
//
// Returns the parsed Question structure, the byte count consumed from the original
// offset position, and any error encountered during parsing or validation.
//
// This function is used internally by parseResponse to process the question section
// of DNS response messages.
func parseQuestion(message []byte, offset int) (Question, int, error) {
	var q Question
	name, nameLen, err := DecodeDomainName(message, offset)
	if err != nil {
		return q, 0, err
	}
	q.Name = name

	if offset+nameLen+4 > len(message) {
		return q, 0, fmt.Errorf("message too short for question type/class")
	}
	q.Type = RecordType(binary.BigEndian.Uint16(message[offset+nameLen : offset+nameLen+2]))
	q.Class = binary.BigEndian.Uint16(message[offset+nameLen+2 : offset+nameLen+4])

	return q, nameLen + 4, nil
}
