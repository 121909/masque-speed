package importer

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"fofa-masque/internal/model"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type row map[string]string

type collector struct {
	endpoints  []model.Endpoint
	seen       map[netip.AddrPort]int
	invalid    int
	duplicates int
}

// Parse imports local FOFA JSON, CSV, or one-IP:port-per-line text. Invalid
// records are skipped with bounded summary warnings; duplicate metadata fills
// only empty values, so the first nonempty value always wins.
func Parse(data []byte, filename string) ([]model.Endpoint, []string, error) {
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 {
		return nil, nil, errors.New("import is empty")
	}
	c := collector{seen: make(map[netip.AddrPort]int)}
	var err error
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	_, _, addressErr := net.SplitHostPort(string(bytes.TrimSpace(firstLine)))
	jsonArray := data[0] == '[' && addressErr != nil
	if data[0] == '{' || jsonArray || strings.EqualFold(filepath.Ext(filename), ".json") {
		err = c.parseJSON(data)
	} else {
		if !utf8.Valid(data) {
			data, err = simplifiedchinese.GB18030.NewDecoder().Bytes(data)
			if err != nil || !utf8.Valid(data) || bytes.Contains(data, []byte("\ufffd")) {
				return nil, nil, errors.New("import is neither valid UTF-8 nor valid GB18030 text")
			}
		}
		if strings.EqualFold(filepath.Ext(filename), ".csv") || bytes.Contains(data, []byte(",")) {
			err = c.parseCSV(data)
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					c.add(row{"host": line})
				}
			}
		}
	}
	warnings := c.warnings()
	if err != nil {
		return nil, warnings, err
	}
	if len(c.endpoints) == 0 {
		return nil, warnings, errors.New("import contains no valid IP:port endpoints (IP must be literal and port must be 1..65535)")
	}
	return c.endpoints, warnings, nil
}

func (c *collector) warnings() []string {
	var warnings []string
	if c.invalid > 0 {
		warnings = append(warnings, fmt.Sprintf("Skipped %d invalid record(s).", c.invalid))
	}
	if c.duplicates > 0 {
		warnings = append(warnings, fmt.Sprintf("Merged %d duplicate record(s); first nonempty metadata values retained.", c.duplicates))
	}
	return warnings
}

func fieldName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ip":
		return "ip"
	case "port", "端口":
		return "port"
	case "host":
		return "host"
	case "country", "country_name", "国家":
		return "country"
	case "region", "province", "省份/地区", "省份", "地区":
		return "region"
	case "city", "城市":
		return "city"
	default:
		return ""
	}
}

func normalizeFields(fields []string) ([]string, error) {
	result := make([]string, len(fields))
	seen := make(map[string]bool)
	for i, field := range fields {
		name := fieldName(field)
		if name != "" && seen[name] {
			return nil, fmt.Errorf("ambiguous duplicate import column %q", field)
		}
		seen[name] = true
		result[i] = name
	}
	if !seen["host"] && !(seen["ip"] && seen["port"]) {
		return nil, errors.New("import columns must include ip and port, or host")
	}
	return result, nil
}

func (c *collector) parseCSV(data []byte) error {
	r := csv.NewReader(bytes.NewReader(data))
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read CSV header: %w", err)
	}
	fields, err := normalizeFields(header)
	if err != nil {
		return err
	}
	// Width errors are isolated to their record, but malformed quoting aborts
	// rather than silently losing a potentially unbounded tail of the file.
	r.FieldsPerRecord = -1
	for {
		values, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read CSV record: %w", err)
		}
		if len(values) != len(fields) {
			c.invalid++
			continue
		}
		item := make(row)
		for i, field := range fields {
			if field != "" {
				item[field] = strings.TrimSpace(values[i])
			}
		}
		c.add(item)
	}
}

func (c *collector) parseJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON import must be valid UTF-8")
	}
	var root json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("decode JSON import: %w", err)
	}
	if root[0] == '[' {
		return c.parseObjects(root)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(root, &envelope); err != nil || envelope == nil {
		return errors.New("JSON import must be an object array, assets object, or fields/results export")
	}
	if assets, ok := envelope["assets"]; ok {
		return c.parseObjects(assets)
	}
	var fields []string
	if err := json.Unmarshal(envelope["fields"], &fields); err != nil || len(fields) == 0 {
		return errors.New("FOFA JSON export requires a nonempty fields array and results array")
	}
	fields, err := normalizeFields(fields)
	if err != nil {
		return err
	}
	var results []json.RawMessage
	if err := json.Unmarshal(envelope["results"], &results); err != nil || results == nil {
		return errors.New("FOFA JSON export requires a results array")
	}
	for _, result := range results {
		var values []json.RawMessage
		if err := json.Unmarshal(result, &values); err != nil || len(values) != len(fields) {
			c.invalid++
			continue
		}
		item := make(row)
		valid := true
		for i, field := range fields {
			if field != "" {
				value, ok := jsonValue(values[i])
				valid = valid && ok
				item[field] = value
			}
		}
		if valid {
			c.add(item)
		} else {
			c.invalid++
		}
	}
	return nil
}

func (c *collector) parseObjects(data []byte) error {
	var objects []json.RawMessage
	if err := json.Unmarshal(data, &objects); err != nil || objects == nil {
		return errors.New("JSON assets must be an array of endpoint objects")
	}
	for _, object := range objects {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(object, &fields); err != nil || fields == nil {
			c.invalid++
			continue
		}
		item := make(row)
		valid := true
		// Iterate names in a stable order to avoid map iteration changing the
		// handling of aliases (e.g. country and country_name) in one object.
		for _, name := range []string{"ip", "port", "host", "country", "country_name", "region", "city"} {
			if raw, exists := fields[name]; exists {
				value, ok := jsonValue(raw)
				valid = valid && ok
				key := fieldName(name)
				if item[key] == "" {
					item[key] = value
				}
			}
		}
		if valid {
			c.add(item)
		} else {
			c.invalid++
		}
	}
	return nil
}

func jsonValue(raw json.RawMessage) (string, bool) {
	if bytes.Equal(raw, []byte("null")) {
		return "", true
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return strings.TrimSpace(value), true
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return string(number), true
	}
	return "", false
}

func (c *collector) add(item row) {
	for key, value := range item {
		item[key] = strings.TrimSpace(value)
	}
	ip, port := item["ip"], item["port"]
	if ip == "" || port == "" {
		hostIP, hostPort, err := hostAddress(item["host"])
		if err != nil {
			c.invalid++
			return
		}
		if ip == "" {
			ip = hostIP
		}
		if port == "" {
			port = hostPort
		}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		c.invalid++
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		c.invalid++
		return
	}
	addr = addr.Unmap()
	key := netip.AddrPortFrom(addr, uint16(p))
	if index, ok := c.seen[key]; ok {
		c.duplicates++
		existing := &c.endpoints[index]
		if existing.Country == "" {
			existing.Country = item["country"]
		}
		if existing.Region == "" {
			existing.Region = item["region"]
		}
		if existing.City == "" {
			existing.City = item["city"]
		}
		return
	}
	c.seen[key] = len(c.endpoints)
	c.endpoints = append(c.endpoints, model.Endpoint{IP: addr.String(), Port: p, Country: item["country"], Region: item["region"], City: item["city"]})
}

func hostAddress(host string) (string, string, error) {
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || u.Hostname() == "" {
			return "", "", errors.New("invalid host URL")
		}
		port := u.Port()
		if port == "" {
			switch strings.ToLower(u.Scheme) {
			case "http":
				port = "80"
			case "https":
				port = "443"
			default:
				return "", "", errors.New("host URL has no port")
			}
		}
		return u.Hostname(), port, nil
	}
	return net.SplitHostPort(host)
}
