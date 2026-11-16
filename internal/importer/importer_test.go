package importer

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"fofa-masque/internal/model"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestParseFormats(t *testing.T) {
	want := []model.Endpoint{{IP: "203.0.113.7", Port: 443, Country: "中国", Region: "浙江", City: "杭州"}}
	cases := []struct{ name, filename, input string }{
		{"API assets", "assets.json", `{"assets":[{"ip":"203.0.113.7","port":443,"host":"ignored.example","country":"中国","region":"浙江","city":"杭州"}]}`},
		{"object array", "upload", `[{"ip":"203.0.113.7","port":"443","country":"中国","region":"浙江","city":"杭州"}]`},
		{"FOFA fields", "export.json", `{"fields":["city","unknown","port","country_name","ip","region"],"results":[["杭州",{},443,"中国","203.0.113.7","浙江"]]}`},
		{"English CSV", "data.csv", "ip,port,host,country,region,city\r\n203.0.113.7,443,,中国,浙江,杭州\r\n"},
		{"Chinese CSV BOM", "data.csv", "\xef\xbb\xbfIP,端口,host,国家,省份/地区,城市\n203.0.113.7,443,,中国,浙江,杭州\n"},
		{"sniff CSV", "upload", "ip,port,country,region,city\n203.0.113.7,443,中国,浙江,杭州\n"},
		{"host fallback", "upload.json", `[{"host":"https://203.0.113.7:443/path?q=1","country":"中国","region":"浙江","city":"杭州"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings, err := Parse([]byte(tc.input), tc.filename)
			if err != nil || len(warnings) != 0 || !reflect.DeepEqual(got, want) {
				t.Fatalf("Parse() = %#v, %v, %v; want %#v without warnings", got, warnings, err, want)
			}
		})
	}
}

func TestParseGB18030CSV(t *testing.T) {
	input := "IP,端口,国家,省份/地区,城市\n203.0.113.8,8443,中国,广东,深圳\n"
	encoded, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	got, warnings, err := Parse(encoded, "export.csv")
	want := []model.Endpoint{{IP: "203.0.113.8", Port: 8443, Country: "中国", Region: "广东", City: "深圳"}}
	if err != nil || len(warnings) != 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, %v, %v; want %#v", got, warnings, err, want)
	}
}

func TestParseTextBoundaries(t *testing.T) {
	input := "\xef\xbb\xbf\n192.0.2.1:1\r\n[2001:0db8:0:0::1]:65535\n\n192.0.2.2:0\n192.0.2.3:65536\nexample.com:443\n192.0.2.4:abc\n192.0.2.5\n[fe80::1%eth0]:443\n999.1.2.3:443\n"
	got, warnings, err := Parse([]byte(input), "endpoints.txt")
	want := []model.Endpoint{{IP: "192.0.2.1", Port: 1}, {IP: "2001:db8::1", Port: 65535}}
	if err != nil || !reflect.DeepEqual(got, want) || len(warnings) != 1 || !strings.Contains(warnings[0], "7 invalid") {
		t.Fatalf("Parse() = %#v, %v, %v; want %#v and 7 invalid records", got, warnings, err, want)
	}
}

func TestParseDeduplicatesAndMergesInOrder(t *testing.T) {
	input := `[
		{"ip":"2001:0db8::1","port":443,"country":"first"},
		{"ip":"192.0.2.1","port":8443,"city":"second"},
		{"ip":"2001:db8:0:0:0:0:0:1","port":"443","country":"conflict","region":"filled"},
		{"ip":"::ffff:192.0.2.1","port":8443,"country":"mapped","city":"conflict"},
		{"ip":"192.0.2.1","port":443}
	]`
	got, warnings, err := Parse([]byte(input), "assets.json")
	want := []model.Endpoint{
		{IP: "2001:db8::1", Port: 443, Country: "first", Region: "filled"},
		{IP: "192.0.2.1", Port: 8443, Country: "mapped", City: "second"},
		{IP: "192.0.2.1", Port: 443},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(warnings) != 1 || !strings.Contains(warnings[0], "2 duplicate") {
		t.Fatalf("Parse() = %#v, %v, %v; want %#v and duplicate summary", got, warnings, err, want)
	}
}

func TestParseHostFallbackAndExplicitInvalidFields(t *testing.T) {
	cases := []struct {
		name, input, ip string
		port            int
		valid           bool
	}{
		{"default https", `[{"host":"https://192.0.2.1/path"}]`, "192.0.2.1", 443, true},
		{"default http", `[{"host":"http://192.0.2.1"}]`, "192.0.2.1", 80, true},
		{"IPv6 URL", `[{"host":"https://[2001:db8::1]:8443/a"}]`, "2001:db8::1", 8443, true},
		{"host port", `[{"host":"[2001:db8::2]:443"}]`, "2001:db8::2", 443, true},
		{"missing port", `[{"ip":"192.0.2.2","host":"https://192.0.2.2:8443"}]`, "192.0.2.2", 8443, true},
		{"missing IP", `[{"port":8443,"host":"http://192.0.2.3"}]`, "192.0.2.3", 8443, true},
		{"null fallback", `[{"ip":null,"port":null,"host":"192.0.2.4:443"}]`, "192.0.2.4", 443, true},
		{"hostname rejected", `[{"host":"https://example.com:443"}]`, "", 0, false},
		{"explicit bad IP", `[{"ip":"example.com","port":443,"host":"https://192.0.2.1"}]`, "", 0, false},
		{"explicit zero port", `[{"ip":"192.0.2.1","port":0,"host":"https://192.0.2.1"}]`, "", 0, false},
		{"fractional port", `[{"ip":"192.0.2.1","port":443.5}]`, "", 0, false},
		{"unknown URL no port", `[{"host":"foo://192.0.2.1"}]`, "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings, err := Parse([]byte(tc.input), "data.json")
			if !tc.valid {
				if err == nil || len(got) != 0 || len(warnings) != 1 {
					t.Fatalf("expected invalid summary and error, got %#v, %v, %v", got, warnings, err)
				}
				return
			}
			if err != nil || len(warnings) != 0 || len(got) != 1 || got[0].IP != tc.ip || got[0].Port != tc.port {
				t.Fatalf("Parse() = %#v, %v, %v", got, warnings, err)
			}
		})
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	cases := []struct{ input, filename string }{
		{"", "data.txt"}, {"\xef\xbb\xbf \n", "data.csv"},
		{"[]", "data.json"}, {"{}", "data.json"}, {"null", "data.json"},
		{`{"assets":null}`, "data.json"}, {`{"assets":{}}`, "data.json"},
		{`[{"ip":"192.0.2.1","port":443}] trailing`, "data.json"},
		{`{"fields":["ip","port"],"results":null}`, "data.json"},
		{`{"fields":["ip","port","PORT"],"results":[]}`, "data.json"},
		{"address,service\n192.0.2.1,443", "data.csv"},
		{"ip,port,IP\n192.0.2.1,443,192.0.2.2", "data.csv"},
		{"ip,port\n192.0.2.1,443\n\"unterminated,443", "data.csv"},
		{"\xff", "data.csv"},
		{"192.0.2.1:443", "data.json"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got, _, err := Parse([]byte(tc.input), tc.filename)
			if err == nil || len(got) != 0 {
				t.Fatalf("expected document error and no partial result, got %#v, %v", got, err)
			}
		})
	}
}

func TestParseInvalidRowsHaveBoundedWarnings(t *testing.T) {
	cases := []struct {
		name, input, filename string
		invalid               int
	}{
		{"objects", `{"assets":[null,7,[],{"ip":[],"port":443},{"ip":"bad","port":443},{"ip":"192.0.2.1","port":443}]}`, "data.json", 5},
		{"results", `{"fields":["ip","port"],"results":[null,{},["192.0.2.2"],["bad",443],["192.0.2.3",true],["192.0.2.1",443]]}`, "data.json", 5},
		{"CSV widths", "ip,port\n192.0.2.2\n192.0.2.3,443,extra\nbad,443\n192.0.2.1,443\n", "data.csv", 3},
		{"many text rows", strings.Repeat("bad:443\n", 1000) + "192.0.2.1:443\n", "data.txt", 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings, err := Parse([]byte(tc.input), tc.filename)
			if err != nil || len(got) != 1 || got[0].IP != "192.0.2.1" || len(warnings) != 1 || !strings.Contains(warnings[0], fmt.Sprintf("%d invalid", tc.invalid)) {
				t.Fatalf("Parse() = %#v, %v, %v", got, warnings, err)
			}
		})
	}
}

func TestParseBracketedIPv6TextAndComments(t *testing.T) {
	for _, input := range []string{
		"[2606:4700:4700::1111]:443\n[2001:db8::1]:8443\n",
		"# Local endpoint list\n\n[2606:4700:4700::1111]:443\n  # skipped comment\n[2001:db8::1]:8443\n",
	} {
		got, warnings, err := Parse([]byte(input), "endpoints.txt")
		want := []model.Endpoint{{IP: "2606:4700:4700::1111", Port: 443}, {IP: "2001:db8::1", Port: 8443}}
		if err != nil || len(warnings) != 0 || !reflect.DeepEqual(got, want) {
			t.Fatalf("Parse() = %#v, %v, %v; want %#v", got, warnings, err, want)
		}
	}
}

func TestParseNormalizesMetadataBeforeMerging(t *testing.T) {
	input := `[
		{"ip":" 192.0.2.1 ","port":" 443 ","country":" 中国 ","region":" 北京 ","city":" \t "},
		{"ip":"192.0.2.1","port":443,"country":" other ","region":" other ","city":" 北京市 "},
		{"ip":" ","port":" ","host":" https://192.0.2.2:8443 ","country":" \t ","region":" 上海 ","city":" 上海市 "}
	]`
	got, warnings, err := Parse([]byte(input), "data.json")
	want := []model.Endpoint{
		{IP: "192.0.2.1", Port: 443, Country: "中国", Region: "北京", City: "北京市"},
		{IP: "192.0.2.2", Port: 8443, Region: "上海", City: "上海市"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(warnings) != 1 || !strings.Contains(warnings[0], "1 duplicate") {
		t.Fatalf("Parse() = %#v, %v, %v; want normalized metadata %#v", got, warnings, err, want)
	}
}

func TestCollectorNormalizesAtMergeBoundary(t *testing.T) {
	c := collector{seen: make(map[netip.AddrPort]int)}
	c.add(row{"ip": " 192.0.2.1 ", "port": " 443 ", "country": " 中国 ", "region": " 北京 ", "city": " \t "})
	c.add(row{"host": " https://192.0.2.1 ", "city": " 北京市 "})
	want := []model.Endpoint{{IP: "192.0.2.1", Port: 443, Country: "中国", Region: "北京", City: "北京市"}}
	if !reflect.DeepEqual(c.endpoints, want) || c.invalid != 0 || c.duplicates != 1 {
		t.Fatalf("collector = %#v; want normalized merged endpoints %#v", c, want)
	}
}
