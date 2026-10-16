package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewJavaProject(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pom.xml")
	writeFile(t, manifest, `<project>
  <groupId>com.oracle.database.mcptoolkit</groupId>
  <artifactId>oracle-db-mcp-toolkit</artifactId>
  <version>1.0.0</version>
</project>`)

	p, err := newJavaProject(manifest)
	if err != nil {
		t.Fatalf("newJavaProject returned error: %v", err)
	}
	if p.Name != "oracle-db-mcp-toolkit" {
		t.Errorf("expected name 'oracle-db-mcp-toolkit', got %q", p.Name)
	}
	if p.Ecosystem != "java" {
		t.Errorf("expected ecosystem 'java', got %q", p.Ecosystem)
	}
}

func TestNewJavaProject_FallsBackToDirNameWhenNoArtifactId(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "unnamed-module")
	manifest := filepath.Join(dir, "pom.xml")
	writeFile(t, manifest, `<project><groupId>com.example</groupId></project>`)

	p, err := newJavaProject(manifest)
	if err != nil {
		t.Fatalf("newJavaProject returned error: %v", err)
	}
	if p.Name != "unnamed-module" {
		t.Errorf("expected fallback name 'unnamed-module', got %q", p.Name)
	}
}

func TestJavaGroupIDDependency(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pom.xml")
	writeFile(t, manifest, `<project>
  <groupId>com.example</groupId>
  <artifactId>my-toolkit</artifactId>
  <dependencies>
    <dependency>
      <groupId>io.modelcontextprotocol.sdk</groupId>
      <artifactId>mcp</artifactId>
      <version>${mcp.version}</version>
    </dependency>
  </dependencies>
</project>`)

	doc, err := readPom(manifest)
	if err != nil {
		t.Fatalf("readPom returned error: %v", err)
	}
	if !javaGroupIDDependency(doc, "io.modelcontextprotocol.sdk") {
		t.Error("expected javaGroupIDDependency to find the io.modelcontextprotocol.sdk dependency")
	}
	if javaGroupIDDependency(doc, "com.unrelated") {
		t.Error("expected javaGroupIDDependency to not match an unrelated groupId")
	}
}

func TestJavaGroupIDDependency_DependencyManagementIsNotConfusedWithRealDependencies(t *testing.T) {
	// <dependencyManagement><dependencies> declares version constraints for
	// a multi-module parent, not this module's own runtime dependencies --
	// must never be mistaken for a real SDK dependency.
	root := t.TempDir()
	manifest := filepath.Join(root, "pom.xml")
	writeFile(t, manifest, `<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <packaging>pom</packaging>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>io.modelcontextprotocol.sdk</groupId>
        <artifactId>mcp</artifactId>
        <version>0.12.1</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`)

	doc, err := readPom(manifest)
	if err != nil {
		t.Fatalf("readPom returned error: %v", err)
	}
	if javaGroupIDDependency(doc, "io.modelcontextprotocol.sdk") {
		t.Error("expected a dependencyManagement-only entry to not count as a real dependency")
	}
}

func TestResolveJavaLocalDeps_CoordinateMatch(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "toolkit")
	sharedDir := filepath.Join(root, "shared-lib")

	writeFile(t, filepath.Join(serverDir, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>shared-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`)
	writeFile(t, filepath.Join(sharedDir, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>shared-lib</artifactId>
</project>`)

	server, _ := newJavaProject(filepath.Join(serverDir, "pom.xml"))
	shared, _ := newJavaProject(filepath.Join(sharedDir, "pom.xml"))
	resolveJavaLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveJavaLocalDeps_UnrelatedCoordinateIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "toolkit")
	writeFile(t, filepath.Join(serverDir, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.0</version>
    </dependency>
  </dependencies>
</project>`)
	server, _ := newJavaProject(filepath.Join(serverDir, "pom.xml"))
	resolveJavaLocalDeps([]*Project{server})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for an unrelated Maven Central dependency, got %v", server.LocalDeps)
	}
}

// Sibling modules are routinely referenced through Maven's built-in
// coordinate expressions rather than a literal groupId; each must resolve to
// the declaring POM's own value so the sibling edge is kept.
func TestResolveJavaLocalDeps_BuiltinGroupIDExpressions(t *testing.T) {
	cases := []struct {
		name       string
		serverPom  string
		wantShared bool
	}{
		{"project.groupId", `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${project.groupId}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, true},
		{"project.groupId inherited from parent", `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId></parent>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${project.groupId}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, true},
		{"project.parent.groupId", `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId></parent>
  <groupId>com.example.tools</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${project.parent.groupId}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, true},
		{"deprecated pom.groupId alias with wrapped whitespace", `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency>
      <groupId>
        ${pom.groupId}
      </groupId>
      <artifactId>shared-lib</artifactId>
    </dependency>
  </dependencies>
</project>`, true},
		{"deprecated unprefixed groupId", `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${groupId}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, true},
		{"deprecated unprefixed parent.groupId", `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId></parent>
  <groupId>com.example.tools</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${parent.groupId}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, true},
		{"user-defined property stays unresolved", `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>${shared.group}</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			serverDir := filepath.Join(root, "toolkit")
			sharedDir := filepath.Join(root, "shared-lib")
			writeFile(t, filepath.Join(serverDir, "pom.xml"), tc.serverPom)
			writeFile(t, filepath.Join(sharedDir, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>shared-lib</artifactId>
</project>`)

			server, err := newJavaProject(filepath.Join(serverDir, "pom.xml"))
			if err != nil {
				t.Fatal(err)
			}
			shared, err := newJavaProject(filepath.Join(sharedDir, "pom.xml"))
			if err != nil {
				t.Fatal(err)
			}
			resolveJavaLocalDeps([]*Project{server, shared})

			gotShared := len(server.LocalDeps) == 1 && server.LocalDeps[0] == shared.Dir
			if gotShared != tc.wantShared || (!tc.wantShared && len(server.LocalDeps) != 0) {
				t.Errorf("server.LocalDeps = %v, want shared-lib edge: %v", server.LocalDeps, tc.wantShared)
			}
		})
	}
}

// A module inside the SDK's own group can depend on the SDK through
// ${project.groupId}; SDK detection must resolve it like local-dependency
// matching does.
func TestJavaGroupIDDependency_ResolvesBuiltinExpressions(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pom.xml")
	writeFile(t, manifest, `<project>
  <parent><groupId>io.modelcontextprotocol.sdk</groupId><artifactId>mcp-parent</artifactId></parent>
  <artifactId>conformance-server</artifactId>
  <dependencies>
    <dependency><groupId>${project.groupId}</groupId><artifactId>mcp</artifactId></dependency>
  </dependencies>
</project>`)
	doc, err := readPom(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !javaGroupIDDependency(doc, "io.modelcontextprotocol.sdk") {
		t.Error("expected ${project.groupId} (inherited io.modelcontextprotocol.sdk) to count as the SDK dependency")
	}
}

// A module's own groupId can be spelled in terms of its parent's, and modules
// that share one reactor-wide property for their groupId must still match
// each other even though that property is never resolved.
func TestResolveJavaLocalDeps_ExpressionsInOwnCoordinates(t *testing.T) {
	cases := []struct {
		name, sharedGroup, depGroup string
	}{
		{"own groupId from the parent", "${project.parent.groupId}", "com.example"},
		{"shared reactor property on both sides", "${revision.group}", "${revision.group}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			serverDir := filepath.Join(root, "toolkit")
			sharedDir := filepath.Join(root, "shared-lib")
			writeFile(t, filepath.Join(serverDir, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>toolkit</artifactId>
  <dependencies>
    <dependency><groupId>`+tc.depGroup+`</groupId><artifactId>shared-lib</artifactId></dependency>
  </dependencies>
</project>`)
			writeFile(t, filepath.Join(sharedDir, "pom.xml"), `<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId></parent>
  <groupId>`+tc.sharedGroup+`</groupId>
  <artifactId>shared-lib</artifactId>
</project>`)
			server, _ := newJavaProject(filepath.Join(serverDir, "pom.xml"))
			shared, _ := newJavaProject(filepath.Join(sharedDir, "pom.xml"))
			resolveJavaLocalDeps([]*Project{server, shared})

			if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
				t.Errorf("server.LocalDeps = %v, want [%s]", server.LocalDeps, shared.Dir)
			}
		})
	}
}
