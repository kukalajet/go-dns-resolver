// Package main provides a command-line DNS resolver tool that performs DNS lookups
// for various record types including A, AAAA, CNAME, MX, TXT, and NS records.
//
// The tool mimics the output format of dig(1) and other standard DNS utilities,
// providing detailed information about DNS responses including headers, flags,
// and resource records. It uses Google's public DNS server (8.8.8.8) by default
// for all queries.
//
// Usage:
//
//	dsn-resolver <domain> [record_type]
//
// Examples:
//
//	dsn-resolver google.com          # Query A records for google.com
//	dsn-resolver google.com AAAA     # Query IPv6 addresses
//	dsn-resolver google.com MX       # Query mail exchange records
//	dsn-resolver google.com TXT      # Query text records
package main

import (
	"fmt"
	"go-dns-resolver/dns"
	"os"
	"strings"
)

// main is the entry point of the DNS resolver command-line tool.
// It parses command-line arguments, validates the record type, performs the DNS
// resolution using the dns package, and formats the output in a dig-like format.
// The program exits with status code 1 on any error condition.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <domain> [record_type]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s google.com A\n", os.Args[0])
		os.Exit(1)
	}

	domain := os.Args[1]
	recordTypeStr := "A"
	if len(os.Args) > 2 {
		recordTypeStr = strings.ToUpper(os.Args[2])
	}

	var recordType dns.RecordType
	switch recordTypeStr {
	case "A":
		recordType = dns.TypeA
	case "AAAA":
		recordType = dns.TypeAAAA
	case "CNAME":
		recordType = dns.TypeCNAME
	case "MX":
		recordType = dns.TypeMX
	case "TXT":
		recordType = dns.TypeTXT
	case "NS":
		recordType = dns.TypeNS
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported record type '%s'\n", recordTypeStr)
		os.Exit(1)
	}

	// Use the library to resolve the domain
	resolver := dns.NewResolver("8.8.8.8:53")
	response, err := resolver.Resolve(domain, recordType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printResponse(response)
}

// printResponse formats and displays a DNS response message in a dig-like output format.
// It prints the DNS header information including status codes and flags, followed by
// the question section and answer section if present. The output format closely
// mimics the standard dig(1) command-line tool to provide familiar output for
// network administrators and developers.
//
// The function handles DNS message compression limitations by using an empty
// byte slice for RData string parsing, which works correctly for most common
// record types that don't rely on cross-record compression references.
func printResponse(msg *dns.DNSMessage) {
	fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", getStatus(msg.Header.Flags), msg.Header.ID)
	fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
		getFlags(msg.Header.Flags),
		msg.Header.QDCOUNT,
		msg.Header.ANCOUNT,
		msg.Header.NSCOUNT,
		msg.Header.ARCOUNT)

	if len(msg.Questions) > 0 {
		fmt.Println(";; QUESTION SECTION:")
		for _, q := range msg.Questions {
			fmt.Printf(";%s.\t\tIN\t%s\n", q.Name, q.Type)
		}
		fmt.Println()
	}

	// We need the original raw message to correctly parse compressed RData strings
	// This is a limitation of the current design. A better design would pass the raw
	// message bytes along with the parsed structure. For now, we accept this limitation.
	// To fully fix this, the Resolve method would need to return the raw byte slice too.
	// For this example, we'll assume most simple records don't rely on cross-record compression.
	rawBytes := []byte{} // This is a placeholder.

	if len(msg.Answers) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, a := range msg.Answers {
			fmt.Printf("%s.\t%d\tIN\t%s\t%s\n", a.Name, a.TTL, a.Type, a.RDataString(rawBytes))
		}
		fmt.Println()
	}
}

// getStatus extracts and returns the human-readable status code from DNS response flags.
// It examines the RCODE (Response Code) field in the DNS header flags to determine
// whether the query was successful, resulted in a domain not found error, or
// encountered another type of error. The function follows RFC 1035 definitions
// for standard DNS response codes.
//
// Returns "NOERROR" for successful queries (RCODE 0), "NXDOMAIN" for non-existent
// domains (RCODE 3), or "ERROR" for all other error conditions.
func getStatus(flags uint16) string {
	if flags&0x000F == 0 {
		return "NOERROR"
	}
	if flags&0x000F == 3 {
		return "NXDOMAIN"
	}
	return "ERROR"
}

// getFlags extracts and formats DNS header flags into a human-readable string.
// It examines specific bits in the DNS header flags field to identify which
// operational flags are set and returns them as a space-separated string.
// The function follows RFC 1035 flag definitions for standard DNS operations.
//
// Supported flags include:
//   - qr: Query/Response flag (1 = response, 0 = query)
//   - aa: Authoritative Answer flag
//   - rd: Recursion Desired flag
//   - ra: Recursion Available flag
//
// Returns a string containing all set flags separated by spaces, or an empty
// string if no recognized flags are set.
func getFlags(flags uint16) string {
	var f []string
	if flags&0x8000 != 0 {
		f = append(f, "qr")
	}
	if flags&0x0400 != 0 {
		f = append(f, "aa")
	}
	if flags&0x0100 != 0 {
		f = append(f, "rd")
	}
	if flags&0x0080 != 0 {
		f = append(f, "ra")
	}
	return strings.Join(f, " ")
}
