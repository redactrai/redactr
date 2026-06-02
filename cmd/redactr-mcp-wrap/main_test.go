package main

import (
	"reflect"
	"testing"
)

func TestResolveChild(t *testing.T) {
	fakeContainer := func(image string, entry []string) ([]string, error) {
		return append([]string{"docker", "run", "--rm", "-i", image}, entry...), nil
	}

	got, err := resolveChild([]string{"my-mcp", "--port", "0"}, fakeContainer)
	if err != nil || !reflect.DeepEqual(got, []string{"my-mcp", "--port", "0"}) {
		t.Fatalf("host child argv = %v err=%v", got, err)
	}

	got, err = resolveChild([]string{"--container", "my-mcp", "--port", "0"}, fakeContainer)
	if err != nil || !reflect.DeepEqual(got, []string{"docker", "run", "--rm", "-i", "redactr-base:local", "my-mcp", "--port", "0"}) {
		t.Fatalf("container argv = %v err=%v", got, err)
	}

	got, _ = resolveChild([]string{"--container", "--image", "reg/x@sha256:abc", "my-mcp"}, fakeContainer)
	if got[4] != "reg/x@sha256:abc" || got[5] != "my-mcp" {
		t.Fatalf("custom image argv = %v", got)
	}
}
