package imagebuild

import (
	"context"
	"strings"
	"testing"
)

type fakeRunner struct{ calls [][]string }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if name == "docker" && len(args) > 0 && args[0] == "push" {
		return "...\nlatest: digest: sha256:" + strings.Repeat("de", 32) + " size: 1234\n", nil
	}
	return "", nil
}

func TestBuildSequence(t *testing.T) {
	fr := &fakeRunner{}
	b := &ShellBuilder{Run: fr.Run, CosignKey: "/keys/cosign.key"}
	res, err := b.Build(context.Background(), BuildSpec{
		Dockerfile: "FROM redactr-base\nRUN echo hi\n",
		BaseRef:    "redactr-base",
		TargetRef:  "reg/acme/tools",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Digest != "sha256:"+strings.Repeat("de", 32) || res.Ref != "reg/acme/tools" {
		t.Fatalf("result = %+v", res)
	}
	if len(fr.calls) != 3 || fr.calls[0][0] != "docker" || fr.calls[0][1] != "build" ||
		fr.calls[1][1] != "push" || fr.calls[2][0] != "cosign" {
		t.Fatalf("call sequence = %v", fr.calls)
	}
	if !strings.Contains(strings.Join(fr.calls[2], " "), "reg/acme/tools@sha256:"+strings.Repeat("de", 32)) {
		t.Errorf("cosign target = %v", fr.calls[2])
	}
}

func TestBuildRejectsNonBaseFrom(t *testing.T) {
	b := &ShellBuilder{Run: (&fakeRunner{}).Run, CosignKey: "k"}
	_, err := b.Build(context.Background(), BuildSpec{
		Dockerfile: "FROM ubuntu:22.04\n", BaseRef: "redactr-base", TargetRef: "reg/x",
	})
	if err == nil {
		t.Fatal("expected rejection of a Dockerfile not based on redactr-base")
	}
}

func TestBuildFromGateExactness(t *testing.T) {
	fr := &fakeRunner{}
	b := &ShellBuilder{Run: fr.Run, CosignKey: "k"}
	// typosquat rejected
	if _, err := b.Build(context.Background(), BuildSpec{Dockerfile: "FROM redactr-base-evil:latest\n", BaseRef: "redactr-base", TargetRef: "r/x"}); err == nil {
		t.Error("typosquat base should be rejected")
	}
	// tagged base accepted
	if _, err := b.Build(context.Background(), BuildSpec{Dockerfile: "FROM redactr-base:v2\nRUN x\n", BaseRef: "redactr-base", TargetRef: "r/x"}); err != nil {
		t.Errorf("tagged base should be accepted: %v", err)
	}
}
