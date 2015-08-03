package main

import (
	"fmt"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Post request struct
type record struct {
	ApiKey string `json:"apiKey"`
	Email string `json:"email"`
	Header string `json:"received"`
}

// Result reply struct
type Reply struct {
	Email string `json:"email"`
	Header string `json:"received"`
	Domain string `json:"domain"`
	IP string `json:"sender-IP"`
	Result string `json:"result"`
}

// Array of valid/invalid API keys
var validAPIKeys = map[string]bool {
	"0000": true,
}

func main() {
		  // Setup logfile
		  tDate := time.Now()
		  var sLogFile string = "logs/spf-" + tDate.Format("2006-01-02") + ".log"
		  fpLog, err := os.OpenFile(sLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		  if err != nil {
					 log.Fatal("Error opening/creating logfile %v", err)
		  }
		  defer fpLog.Close()
		  log.SetOutput(fpLog)

	log.Printf("Starting spf service ...")

	// Start listener on HTTP port so we can use pinging services to verify service up
	http.HandleFunc("/", HandleHTTP)
	http.ListenAndServe(":8112", nil)

	log.Printf("Stopping spf service ...")
}

// HTTP API handler
func HandleHTTP(w http.ResponseWriter, r *http.Request) {
	var post record
	var p *json.Decoder

	// Decode json request
	p = json.NewDecoder(r.Body)
	err := p.Decode(&post)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Bad request"}`))
		log.Printf("Error: Received a request that I couldn't handle. %v", err)
		return
	}

	// Validate API Key
	if !ValidateAPIKey(post.ApiKey) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Unauthorized; requires valid API key"}`))
		log.Printf("Error: Invalid API key. %s", post.ApiKey)
		return
	// Valid API Key continue
	} else {
		// Inspect received header and extract the sender hostname/IP
		sReceived, err := ExtractSendingServer(post.Header)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Bad request"}`))
			log.Printf("Error: Cannot resolve sending server %s. %v", post.Header, err)
			return
		}

		// Now with sender, get SPF records and test if valid sender
		r, err := Process(post.Email, sReceived)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Bad request"}`))
			log.Printf("Error: Cannot process SPF. %v", err)
			return
		}

		// Convert reply to a JSON string
		reply, err := json.Marshal(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Bad request"}`))
			log.Printf("Error: Failed to marshal json. %v", err)
			return
		}

		// Give good reply
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(reply))
		log.Printf("%s", reply)
	}
}

// Recursively takes an spf record and resolves into a list of IP addresses
//TODO: Handle IPv6 addresses. Currently ignoring due to the huge
//		performance hit. Too slow.
func TraverseSPF(records []string) string {
	var expandedSPF string
	var recordArr []string

	for _, record := range records {
		// Skip non SPF TXT records
		if !strings.Contains(record, "spf") {
			continue
		}

		//fmt.Printf("\nExpanding \"%s\"", record)

		// Explode record on spaces
		recordArr = strings.Split(record, " ")
		//fmt.Printf("\nSplit \"%q\"", recordArr)

		// Loop through all directives and process
		for _, r := range recordArr {
			// Lines start with - are fails
			if strings.HasPrefix(r, "-") {
				continue
			}
			// Get TXT records and for each include
			if strings.Contains(r, "include:") {
				temp := strings.Replace(strings.Replace(strings.Replace(r, "+include:", "", -1), "~include:", "", -1), "include:", "", -1)
				passArr, _ := net.LookupTXT(temp)
				//fmt.Printf("\n	Found include")
				expandedSPF = expandedSPF + " " + TraverseSPF(passArr)
			// Expand redirects
			} else if strings.Contains(r, "redirect=") {
				passArr, _ := net.LookupTXT(strings.Replace(r, "redirect=", "", -1))
				//fmt.Printf("\n	Found redirect")
				expandedSPF = expandedSPF + " " + TraverseSPF(passArr)
			// If contains mx get mx records
			} else if strings.Contains(r, "mx:") {
				//TODO: Add MX expansion
				// Currently this is just ignoring mx records as if they were invalid
				//passArr, _ := net.LookupMX(strings.Replace(r, "mx:", "", -1))
				//fmt.Printf("\n	Found mx")
				//expandedSPF = expandedSPF + " " + TraverseSPF(passArr)
			} else {
				//fmt.Printf("\n	Nothing to expand")
				expandedSPF = expandedSPF + " " + r
			}
		}
	}

	return expandedSPF
}

// Check valid API key
func ValidateAPIKey(apiKey string) bool {
	return validAPIKeys[apiKey]
}

// Process request
func Process(sEmail string, sHeader string) (Reply, error) {
	var r Reply
	var sIP string
	var sDomain string
	var sReceived = sHeader
	var bSPFPass bool = false
	var ApprovedIPs []string

	// Init
	_, sDomain = SplitAddress(sEmail)
	r.Email = sEmail
	r.Header = sHeader
	r.Domain = sDomain
	r.IP = sIP

	// Get records of sender domain
	records, _ := net.LookupTXT(sDomain)
	sSPF := TraverseSPF(records)
	//fmt.Printf("\n\n\nFinal: %s", sSPF)
	SPF := strings.Split(sSPF, " ")

	// Now let's only look at IPs
	for _, el := range SPF {
		if (strings.Contains(el, "ip4:")) {
			ApprovedIPs = append(ApprovedIPs, el)
		}
		//TODO: ipv6
	}
	

	// See if received from is valid sender
	ips, _ := net.LookupIP(sReceived)
	for _, ip := range ips {
		//fmt.Printf("\nFound %v", ip)
		r.IP = ip.String()
		for _, el := range ApprovedIPs {
			// See if IP in spf
			if strings.Contains(el, ip.String()) {
				bSPFPass = true
				break
			// If this is a network block, do lookup
			} else if strings.Contains(el, "/") {
				//fmt.Printf("\n	Resolving cidr of %v", el)
				_, cidrNet, _ := net.ParseCIDR(strings.Replace(strings.Replace(el, "ip4:", "", -1), "ip6:", "", -1))
				if cidrNet.Contains(ip) {
					bSPFPass = true
					break
				}
			}
		}

		// See if IP in any networks of spf
	}

	//fmt.Printf("\n\n")
	//for _, ip := range ips {
	//	fmt.Printf("\nSent by %s", ip.String())
	//}

	// Build success reply
	r.Result = "Fail"
	if bSPFPass {
		r.Result = "Pass"
	}

	return r, nil
}

// Extract sender and domain from email address
func SplitAddress(sEmail string) (string, string) {
	var sMailbox, sDomain string

	// Separate address into mailbox@domain
	sPieces := strings.Split(sEmail, "@")
	sMailbox = sPieces[0]
	sDomain = sPieces[1]

	return sMailbox, sDomain
}

// Extract sending address from email's received headers
func ExtractSendingServer(sHeader string) (string, error) {
	var h string = ""
	var parts []string = strings.Split(sHeader, " ")

	for _, el := range parts {
		// If domain, IP, etc. add
		if strings.Contains(el, ".") {
			// Find records
			regex := regexp.MustCompile("([0-9]{1,3}[.]){3}[0-9]{1,3}")
			//regex := regexp.MustCompile("([0-9a-zA-Z-]+[.])+([0-9a-zA-Z-]+)+")
			match := regex.FindStringSubmatch(el)

			if len(match) > 0 {
                        	h += match[0]
			}
		}
	}

	if len(h) < 1 {
		return h, fmt.Errorf("Error: Unable to parse received header.")
	}

	return h, nil
}
