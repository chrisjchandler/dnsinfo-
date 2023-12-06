package main

import (
    "encoding/json"
    "net/http"
    "github.com/miekg/dns"
)

// DNSRecord specifications library does support more record types
type DNSRecords struct {
    A     []string `json:"a,omitempty"`
    AAAA  []string `json:"aaaa,omitempty"`
    CNAME []string `json:"cname,omitempty"`
    MX    []string `json:"mx,omitempty"`
    NS    []string `json:"ns,omitempty"`
    TXT   []string `json:"txt,omitempty"`
    // Add other record types as needed just make sure they're supported by the library
}

// handleDNSQuery with JSON formatting
func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
    domain := r.URL.Query().Get("domain")
    nameserver := r.URL.Query().Get("nameserver") // Example: "1.1.1.1"

    // Input validation
    if domain == "" || nameserver == "" {
        http.Error(w, "Missing domain or nameserver", http.StatusBadRequest)
        return
    }

    records, err := queryAllRecordTypes(domain, nameserver)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(records)
}

// queryAllRecordTypes queries all DNS record types listed in the struct above for a given domain and nameserver
func queryAllRecordTypes(domain, nameserver string) (DNSRecords, error) {
    var records DNSRecords
    recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypeTXT}

    for _, recordType := range recordTypes {
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(domain), recordType)
        m.RecursionDesired = true

        c := new(dns.Client)
        in, _, err := c.Exchange(m, nameserver+":53")
        if err != nil {
            return records, err
        }

        for _, answer := range in.Answer {
            switch answer.Header().Rrtype {
            case dns.TypeA:
                if aRecord, ok := answer.(*dns.A); ok {
                    records.A = append(records.A, aRecord.A.String())
                }
            case dns.TypeAAAA:
                if aaaaRecord, ok := answer.(*dns.AAAA); ok {
                    records.AAAA = append(records.AAAA, aaaaRecord.AAAA.String())
                }
            case dns.TypeCNAME:
                if cnameRecord, ok := answer.(*dns.CNAME); ok {
                    records.CNAME = append(records.CNAME, cnameRecord.Target)
                }
            case dns.TypeMX:
                if mxRecord, ok := answer.(*dns.MX); ok {
                    records.MX = append(records.MX, mxRecord.Mx)
                }
            case dns.TypeNS:
                if nsRecord, ok := answer.(*dns.NS); ok {
                    records.NS = append(records.NS, nsRecord.Ns)
                }
            case dns.TypeTXT:
                if txtRecord, ok := answer.(*dns.TXT); ok {
                    records.TXT = append(records.TXT, txtRecord.Txt...)
                }
            }
        }
    }
    return records, nil
}

func main() {
    http.HandleFunc("/dns-query", handleDNSQuery)
    http.ListenAndServe(":8080", nil)
}
