package libmcp

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseConfigAuthPolicy(t *testing.T) {
	data := []byte(`{"mcpServers":{"s":{"url":"https://x.example","auth_policy":{"protected":["a","b"],"public":["c"],"repeatable":["a"]}}}}`)
	servers, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	want := AuthPolicy{Protected: []string{"a", "b"}, Public: []string{"c"}, Repeatable: []string{"a"}}
	if len(servers) != 1 || !reflect.DeepEqual(servers[0].AuthPolicy, want) {
		t.Fatalf("auth_policy = %+v, want %+v", servers, want)
	}
}

func TestParseConfigAuthPolicyConflict(t *testing.T) {
	data := []byte(`{"mcpServers":{"s":{"url":"https://x.example","auth_policy":{"protected":["a"],"public":["a"]}}}}`)
	_, err := ParseConfig(data)
	if err == nil || !strings.Contains(err.Error(), "both protected and public") {
		t.Fatalf("want conflict error, got %v", err)
	}
}
