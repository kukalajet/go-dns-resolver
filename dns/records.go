package dns

import (
	"encoding/binary"
	"fmt"
)

// RecordType represents the type of a DNS resource record as defined in RFC 1035.
// It identifies the format and meaning of the resource record's data section.
type RecordType uint16

const (
	// TypeA represents an IPv4 address record (RFC 1035).
	TypeA RecordType = 1
	// TypeAAAA represents an IPv6 address record (RFC 3596).
	TypeAAAA RecordType = 28
	// TypeCNAME represents a canonical name record that aliases one name to another (RFC 1035).
	TypeCNAME RecordType = 5
	// TypeMX represents a mail exchange record that specifies mail servers for a domain (RFC 1035).
	TypeMX RecordType = 15
	// TypeTXT represents a text record containing arbitrary human-readable text (RFC 1035).
	TypeTXT RecordType = 16
	// TypeNS represents a name server record that delegates a DNS zone to an authoritative server (RFC 1035).
	TypeNS RecordType = 2
)

// String returns the standard string representation of the DNS record type.
// For known types, it returns the conventional name (e.g., "A", "AAAA").
// For unknown types, it returns a generic format "TYPEn" where n is the numeric value.
func (rt RecordType) String() string {
	switch rt {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeNS:
		return "NS"
	default:
		return fmt.Sprintf("TYPE%d", rt)
	}
}

// ResourceRecord represents a DNS resource record as defined in RFC 1035 Section 4.1.3.
// It contains all the fields that comprise a resource record in a DNS message:
// the domain name, record type, class, time-to-live, and the record-specific data.
type ResourceRecord struct {
	Name     string
	Type     RecordType
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// ParseResourceRecord extracts a DNS resource record from a binary DNS message.
// It parses the resource record starting at the given offset in the message buffer
// and returns the parsed record, the new offset after the record, and any error encountered.
//
// The function handles DNS name compression for the domain name field and validates
// that all required fields can be read from the message without exceeding boundaries.
// The returned offset points to the byte immediately following the parsed record.
func ParseResourceRecord(message []byte, offset int) (ResourceRecord, int, error) {
	var rr ResourceRecord

	name, nameLen, err := DecodeDomainName(message, offset)
	if err != nil {
		return rr, 0, fmt.Errorf("failed to parse RR name: %w", err)
	}
	rr.Name = name
	offset += nameLen

	if offset+10 > len(message) {
		return rr, 0, fmt.Errorf("message too short for RR header fields")
	}

	rr.Type = RecordType(binary.BigEndian.Uint16(message[offset : offset+2]))
	rr.Class = binary.BigEndian.Uint16(message[offset+2 : offset+4])
	rr.TTL = binary.BigEndian.Uint32(message[offset+4 : offset+8])
	rr.RDLength = binary.BigEndian.Uint16(message[offset+8 : offset+10])
	offset += 10

	if offset+int(rr.RDLength) > len(message) {
		return rr, 0, fmt.Errorf("RR data length exceeds message boundary")
	}

	rr.RData = make([]byte, rr.RDLength)
	copy(rr.RData, message[offset:offset+int(rr.RDLength)])
	offset += int(rr.RDLength)

	return rr, offset, nil
}
