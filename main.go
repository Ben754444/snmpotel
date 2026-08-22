package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/types"
	"go.opentelemetry.io/contrib/bridges/otelslog"
)

var version = "CIVERSION"

var logger = otelslog.NewLogger("snmpotel")
var (
	oidIndex   = make(map[string]gosmi.SmiNode)
	oidIndexMu sync.RWMutex
)

func main() {
	log.Println("running version", version)
	listenAddr := flag.String("listen", "0.0.0.0:162", "UDP or TCP address to listen on")
	flag.Parse()

	ctx := context.Background()
	shutdown, err := InitLoggerProvider(ctx, "snmpotel")
	if err != nil {
		panic(err)
	}
	defer shutdown(ctx)

	// initialize MIB subsystem (best-effort)
	initMIBs()

	for _, m := range gosmi.GetLoadedModules() {
		fmt.Println(m.Name)
	}

	listener := gosnmp.NewTrapListener()
	listener.Params = gosnmp.Default
	listener.Params.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", 0))
	listener.OnNewTrap = handleTrap
	log.Printf("listen on %s", *listenAddr)

	if err := listener.Listen(*listenAddr); err != nil {
		log.Fatalf("listen on %s: %v", *listenAddr, err)
	}

}

func initMIBs() {
	gosmi.Init()

	gosmi.AppendPath("./mibs")

	if p := os.Getenv("MIB_MODULES"); p != "" {
		for _, module := range strings.Split(p, ",") {
			module = strings.TrimSpace(module)
			//log.Printf("loading module %s", module)
			if module != "" {
				if _, err := gosmi.LoadModule(module); err != nil {
					log.Printf("load module %s: %v", module, err)

				}
			}

		}
	}

	buildOIDIndex()
}
func handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	ptr := lookupPTR(addr.IP.String())

	eventDescription := "Received SNMP Trap"

	logData := map[string]any{
		"snmp.enterprise": packet.Enterprise,
		"snmp.agent":      packet.AgentAddress,
		"snmp.agent_ptr":  ptr,
		"snmp.generic":    packet.GenericTrap,
		"snmp.specific":   packet.SpecificTrap,
		"snmp.uptime":     packet.Timestamp,
	}
	resolvedEnterprise := ""
	var err error
	if packet.Enterprise != "" {
		resolvedEnterprise, _, err = resolveTrapOID(packet.Enterprise)
	}
	if err == nil {
		log.Println("resolved enterprise OID:", resolvedEnterprise)
		logData["snmp.enterprise"] = resolvedEnterprise
	}

	for _, variable := range packet.Variables {
		resolved, node, err := resolveTrapOID(variable.Name)
		if err != nil {
			log.Printf("resolve OID %s: %v", variable.Name, err)
			continue
		}

		value := parseValue(variable, node)

		if resolved == "eventDescription" {
			eventDescription = cleanDescription(value)
		}

		if resolved == "snmpTrapOID" { // snmpTrapOid has a value of another OID, we need to resolve that
			resolvedTrapOID, _, err := resolveTrapOID(value)
			if err != nil {
				log.Printf("resolve trap OID %s: %v", value, err)
			} else {
				logData["snmpTrap"] = resolvedTrapOID
			}
		}

		logData[resolved] = value
	}

	printJSON(logData)

	args := make([]any, 0, len(logData)*2)

	for key, value := range logData {
		args = append(args, key, value)
	}

	// check if the switch is manufactured by hp

	if eventDescription == "Received SNMP Trap" {
		logger.Debug(eventDescription, args...)
	} else {
		if strings.HasPrefix(packet.Enterprise, ".1.3.6.1.4.1.11.2.3.7.11") { //hpEtherSwitch
			hpVendorSpecific := extractHPLogFields(eventDescription)
			args = append(args, "severity", hpVendorSpecific.severity.String())
			args = append(args, "date", hpVendorSpecific.date)
			args = append(args, "time", hpVendorSpecific.time)
			args = append(args, "messageId", hpVendorSpecific.id)
			args = append(args, "module", hpVendorSpecific.module)
			logger.Log(context.Background(), hpVendorSpecific.severity, hpVendorSpecific.message, args...)
		} else {
			logger.Info(eventDescription, args...)
		}
	}
}

func printJSON(data map[string]interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("marshal event: %v", err)
		return
	}

	fmt.Println(string(b))
}

func cleanDescription(desc string) string {
	newStr := ""
	for i, char := range desc {
		if char == '\n' || char == '\r' || !unicode.IsPrint(char) {
			continue
		}
		// remove double spaces
		if char == ' ' && i+1 < len(desc) && desc[i+1] == ' ' {
			continue
		}

		newStr += string(char)
	}
	return newStr
}

func lookupPTR(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}

	return strings.TrimSuffix(names[0], ".")
}

func buildOIDIndex() {
	oidIndexMu.Lock()
	defer oidIndexMu.Unlock()

	oidIndex = make(map[string]gosmi.SmiNode)
	for _, module := range gosmi.GetLoadedModules() {
		for _, node := range module.GetNodes() {
			key := normalizeOID(node.RenderNumeric())
			if key == "" {
				continue
			}
			if existing, ok := oidIndex[key]; !ok || node.OidLen > existing.OidLen {
				oidIndex[key] = node
			}
		}
	}
}

func resolveTrapOID(oid string) (string, gosmi.SmiNode, error) {
	node, err := gosmi.GetNodeByOID(types.OidMustFromString(normalizeOID(oid)))
	if err != nil {
		return oid, gosmi.SmiNode{}, fmt.Errorf("resolve OID %s: %w", oid, err)
	}

	return node.Name, node, nil
}

func normalizeOID(oid string) string {
	s := strings.TrimSpace(oid)
	if strings.HasPrefix(s, ".") {
		s = strings.TrimPrefix(s, ".")
	}
	return s
}

func parseValue(pdu gosnmp.SnmpPDU, node gosmi.SmiNode) string {
	switch pdu.Type {
	case gosnmp.Integer:
		return fmt.Sprintf("%d", pdu.Value)

	case gosnmp.Counter32,
		gosnmp.Gauge32,
		gosnmp.TimeTicks,
		gosnmp.Counter64:
		return fmt.Sprintf("%v", pdu.Value)

	case gosnmp.ObjectIdentifier:
		return fmt.Sprintf("%v", pdu.Value)

	case gosnmp.IPAddress:
		return fmt.Sprintf("%v", pdu.Value)

	case gosnmp.OctetString:
		return parseOctetString(pdu.Value, node)

	case gosnmp.Null:
		return ""

	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func parseOctetString(value any, node gosmi.SmiNode) string {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Sprintf("%v", value)
	}

	if len(b) == 0 {
		return ""
	}

	// MIB textual convention has priority over byte interpretation.
	if tc := textualConvention(node); tc != "" {
		switch tc {
		case "InetAddress":
			return formatInetAddress(b)

		case "DateAndTime":
			if value, ok := parseDateAndTime(b); ok {
				return value
			}

		case "DisplayString":
			return formatDisplayString(b)

		case "PhysAddress":
			return formatPhysAddress(b)
		}
	}

	// Only interpret an OCTET STRING as text when it really looks
	// like printable UTF-8.
	if utf8.Valid(b) && isPrintableString(b) {
		return string(b)
	}

	// Never lose arbitrary binary data.
	return hex.EncodeToString(b)
}

func formatInetAddress(b []byte) string {
	switch len(b) {
	case net.IPv4len:
		return net.IPv4(b[0], b[1], b[2], b[3]).String()

	case net.IPv6len:
		return net.IP(b).String()

	default:
		return hex.EncodeToString(b)
	}
}

func formatPhysAddress(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	parts := make([]string, len(b))

	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}

	return strings.Join(parts, ":")
}

func formatDisplayString(b []byte) string {
	if !utf8.Valid(b) {
		return hex.EncodeToString(b)
	}

	return strings.TrimRight(string(b), "\x00")
}

func textualConvention(node gosmi.SmiNode) string {
	if node.Type == nil {
		return ""
	}

	// SmiType.Name is the textual convention/type name.
	//
	// Examples:
	//   InetAddress
	//   DateAndTime
	//   DisplayString
	//   PhysAddress
	return node.Type.Name
}

func isPrintableString(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}

	return true
}

func parseDateAndTime(b []byte) (string, bool) {
	if len(b) != 8 && len(b) != 11 {
		return "", false
	}

	// SNMP DateAndTime:
	//
	// 1-2:  year, big endian
	// 3:    month
	// 4:    day
	// 5:    hour
	// 6:    minute
	// 7:    second
	// 8:    decisecond
	//
	// 9:    timezone direction ('+' or '-') [optional]
	// 10:   timezone hours                  [optional]
	// 11:   timezone minutes                 [optional]

	year := int(b[0])<<8 | int(b[1])
	month := int(b[2])
	day := int(b[3])
	hour := int(b[4])
	minute := int(b[5])
	second := int(b[6])
	deci := int(b[7])

	// Validate before constructing time.Time.
	if year < 1 ||
		month < 1 || month > 12 ||
		day < 1 || day > 31 ||
		hour > 23 ||
		minute > 59 ||
		second > 59 ||
		deci > 9 {
		return "", false
	}

	loc := time.UTC

	if len(b) == 11 {
		sign := b[8]

		if sign != '+' && sign != '-' {
			return "", false
		}

		tzHours := int(b[9])
		tzMinutes := int(b[10])

		if tzHours > 13 || tzMinutes > 59 {
			return "", false
		}

		offset := (tzHours*60 + tzMinutes) * 60

		if sign == '-' {
			offset = -offset
		}

		loc = time.FixedZone("", offset)
	}

	t := time.Date(
		year,
		time.Month(month),
		day,
		hour,
		minute,
		second,
		deci*100_000_000,
		loc,
	)

	return t.Format(time.RFC3339Nano), true
}
