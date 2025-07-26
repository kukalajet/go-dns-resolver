package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// RecordType represents the numeric identifier for DNS resource record types as defined in RFC 1035.
// It determines how the resource record's data section should be interpreted and formatted.
// The type value is transmitted as a 16-bit unsigned integer in DNS messages.
type RecordType uint16

const (
	// TypeA identifies IPv4 address records that map domain names to 32-bit IPv4 addresses.
	// This is the most common DNS record type for resolving hostnames to IP addresses.
	TypeA RecordType = 1

	// TypeAAAA identifies IPv6 address records that map domain names to 128-bit IPv6 addresses.
	// Defined in RFC 3596, this record type enables IPv6 address resolution.
	TypeAAAA RecordType = 28

	// TypeCNAME identifies canonical name records that create aliases from one domain name to another.
	// CNAME records redirect DNS queries from an alias name to the canonical (true) name.
	TypeCNAME RecordType = 5

	// TypeMX identifies mail exchange records that specify the mail servers responsible for a domain.
	// MX records include a priority value to enable load balancing and failover between mail servers.
	TypeMX RecordType = 15

	// TypeTXT identifies text records that store arbitrary human-readable text data.
	// TXT records are commonly used for domain verification, security policies, and configuration data.
	TypeTXT RecordType = 16

	// TypeNS identifies name server records that delegate authority for a DNS zone to specific name servers.
	// NS records define which servers are authoritative for answering queries about a particular domain.
	TypeNS RecordType = 2
)

// String returns the standard textual representation of the DNS record type.
// It converts numeric record type values to their conventional string names used in DNS tools and documentation.
// For well-known types, it returns the standard abbreviation (e.g., "A", "AAAA", "CNAME").
// For unrecognized types, it returns a generic format "TYPEn" where n is the numeric value,
// following the convention established by RFC 3597 for unknown RR types.
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

// ResourceRecord represents a complete DNS resource record as specified in RFC 1035 Section 4.1.3.
// It encapsulates all the standard fields that comprise a resource record in DNS messages:
// the owner name, record type, class, time-to-live, and the type-specific resource data.
//
// The structure follows the wire format used in DNS message transmission, where RDLength
// indicates the byte length of the RData field. The RData field contains the actual
// resource-specific information whose format depends on the Type field.
//
// Example usage:
//
//	rr := ResourceRecord{
//	    Name:  "example.com",
//	    Type:  TypeA,
//	    Class: 1, // IN (Internet)
//	    TTL:   3600,
//	}
type ResourceRecord struct {
	// Name is the domain name that owns this resource record.
	// It identifies the node in the domain name space to which this record pertains.
	Name string

	// Type specifies the meaning and format of the data in the RData field.
	// It determines how the RData should be interpreted and displayed.
	Type RecordType

	// Class identifies the protocol family or instance of a protocol.
	// In practice, this is almost always 1 (IN for Internet class).
	Class uint16

	// TTL specifies the time interval in seconds that the record may be cached.
	// A value of 0 indicates the record should not be cached.
	TTL uint32

	// RDLength specifies the length in bytes of the RData field.
	// This field is used during parsing to determine where the record ends.
	RDLength uint16

	// RData contains the resource-specific data whose format depends on the Type field.
	// For example, A records contain 4-byte IPv4 addresses, while CNAME records contain domain names.
	RData []byte
}

// ParseResourceRecord extracts a single DNS resource record from a binary DNS message.
// It reads and parses the resource record starting at the specified byte offset within the message buffer,
// returning the parsed record, the updated offset position, and any parsing error encountered.
//
// The function correctly handles DNS name compression when parsing the owner name field and validates
// that all required fields can be safely read without exceeding the message boundaries.
// The returned offset points to the first byte immediately following the parsed record,
// allowing for sequential parsing of multiple records.
//
// Parameters:
//   - message: The complete DNS message buffer containing the resource record
//   - offset: The byte position where the resource record begins
//
// Returns:
//   - ResourceRecord: The parsed resource record with all fields populated
//   - int: The new offset pointing to the byte after this record
//   - error: Any error encountered during parsing, such as malformed data or boundary violations
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

// RDataString converts the binary resource data to a human-readable string representation.
// It interprets the RData field according to the record type and formats it appropriately
// for display or logging purposes. The method handles DNS name compression by requiring
// the complete original message to resolve any compressed domain names in the RData.
//
// For unsupported record types or malformed data, it returns a descriptive error message
// rather than failing, making it safe to use for debugging and logging purposes.
//
// Supported formats:
//   - A records: dotted decimal notation (e.g., "192.0.2.1")
//   - AAAA records: colon-separated hexadecimal notation (e.g., "2001:db8::1")
//   - CNAME/NS records: fully qualified domain names with compression resolved
//   - MX records: preference value followed by exchange domain (e.g., "10 mail.example.com")
//   - TXT records: quoted strings concatenated with spaces
//
// Parameters:
//   - fullMessage: The complete DNS message buffer needed to resolve compressed names
//
// Returns:
//   - string: Human-readable representation of the resource data
func (rr *ResourceRecord) RDataString(fullMessage []byte) string {
	switch rr.Type {
	case TypeA:
		if len(rr.RData) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rr.RData[0], rr.RData[1], rr.RData[2], rr.RData[3])
		}
	case TypeAAAA:
		if len(rr.RData) == 16 {
			var parts []string
			for i := 0; i < 16; i += 2 {
				parts = append(parts, fmt.Sprintf("%x", binary.BigEndian.Uint16(rr.RData[i:i+2])))
			}
			return strings.Join(parts, ":")
		}
	case TypeCNAME, TypeNS:
		// The RData for CNAME/NS is another domain name, which might be compressed.
		// We need to find the start of the RData in the full message to resolve pointers.
		rdataStartOffset := bytes.Index(fullMessage, rr.RData)
		if rdataStartOffset == -1 {
			return "invalid CNAME/NS data"
		}
		name, _, err := DecodeDomainName(fullMessage, rdataStartOffset)
		if err == nil {
			return name
		}
	case TypeMX:
		if len(rr.RData) > 2 {
			preference := binary.BigEndian.Uint16(rr.RData[0:2])
			rdataStartOffset := bytes.Index(fullMessage, rr.RData)
			if rdataStartOffset == -1 {
				return "invalid MX data"
			}
			exchange, _, err := DecodeDomainName(fullMessage, rdataStartOffset+2)
			if err == nil {
				return fmt.Sprintf("%d %s", preference, exchange)
			}
		}
	case TypeTXT:
		var texts []string
		data := rr.RData
		for len(data) > 0 {
			length := int(data[0])
			if len(data) > length {
				texts = append(texts, fmt.Sprintf("%q", string(data[1:1+length])))
				data = data[1+length:]
			} else {
				break
			}
		}
		return strings.Join(texts, " ")
	}
	return fmt.Sprintf("unsupported record type or malformed data (%v)", rr.RData)
}
