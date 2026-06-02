package hooks

var DefaultSafeCmds = []string{
	"cat", "head", "tail", "less", "more", "bat",
	"ls", "tree", "locate",
	"grep", "rg", "ag", "ack", "fgrep", "egrep",
	"cut", "sort", "uniq", "wc", "tr", "column",
	"file", "stat", "du", "df", "which", "whereis", "type",
	"diff", "cmp", "comm",
	"date", "cal", "uptime", "whoami", "hostname", "uname", "printenv",
	"echo", "printf", "basename", "dirname", "realpath",
	"git blame", "git branch", "git diff", "git log", "git ls-files",
	"git remote", "git rev-parse", "git show", "git stash list",
	"git status", "git tag",
	"pwd", "find", "env",
}

func BuildAllowlist(defaults []string, added, removed []string) []string {
	allowed := make(map[string]bool)
	for _, cmd := range defaults {
		allowed[cmd] = true
	}
	for _, cmd := range added {
		allowed[cmd] = true
	}
	for _, cmd := range removed {
		delete(allowed, cmd)
	}
	var result []string
	for cmd := range allowed {
		result = append(result, cmd)
	}
	return result
}
