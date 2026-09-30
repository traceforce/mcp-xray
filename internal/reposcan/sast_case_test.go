package reposcan

import (
	"context"
	"testing"
)

// Lines are lowercased before matching, so a rule written with uppercase letters
// (True, Function, execSync, JSON, ...) must still fire on real code.
func TestDetectUnsafeCommandsMixedCaseRules(t *testing.T) {
	cases := []struct {
		rule string
		line string
	}{
		{"python_subprocess_shell", `subprocess.Popen(cmd, shell=True)`},
		{"python_pickle_loads", `pickle.Unpickler(f)`},
		{"python_yaml_load", `yaml.FullLoader(stream)`},
		{"nodejs_function_constructor", `const f = new Function(body);`},
		{"nodejs_child_process_exec", `child_process.execSync(cmd)`},
		{"nodejs_settimeout_string", `setTimeout("doIt()", 10)`},
		{"nodejs_fs_writefile", `fs.writeFileSync(p, data)`},
		{"nodejs_serialize_eval", `eval(JSON.parse(s))`},
		{"nodejs_vm_runincontext", `vm.runInNewContext(code, ctx)`},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			matches := DetectUnsafeCommands(context.Background(), "x", c.line)
			for _, m := range matches {
				if m.PatternID == c.rule {
					return
				}
			}
			t.Errorf("rule %s did not fire on %q (got %v)", c.rule, c.line, matches)
		})
	}
}
