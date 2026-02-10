package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/scrapli/scrapligo/channel"
	"github.com/scrapli/scrapligo/driver/network"
	opoptions "github.com/scrapli/scrapligo/driver/opoptions"
	driveroptions "github.com/scrapli/scrapligo/driver/options"
	scraplilogging "github.com/scrapli/scrapligo/logging"
	"github.com/scrapli/scrapligo/platform"
	"github.com/scrapli/scrapligo/transport"
	"github.com/scrapli/scrapligo/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Lab struct {
	Name     string `yaml:"name"`
	Topology struct {
		Nodes map[string]Node `yaml:"nodes"`
	} `yaml:"topology"`
}

type Node struct {
	Kind     string `yaml:"kind"`
	MgmtIPv4 string `yaml:"mgmt-ipv4"`
}

type NodeInfo struct {
	Name string
	Kind string
	Host string
}

type Creds struct {
	User string
	Pass string
}

var errUnsupportedKind = errors.New("unsupported kind")

const (
	retryAttempts              = 3
	retryDelay                 = 2 * time.Second
	defaultOpTimeout           = 5 * time.Minute
	ciscoHandshakeAttempts     = 3
	ciscoHandshakeRetryDelay   = 3 * time.Second
	ciscoRestorePostUploadWait = 2 * time.Second
)

var opTimeout = defaultOpTimeout
var scrapliLogger *scraplilogging.Instance
var ciscoTimestampLinePattern = regexp.MustCompile(
	`^[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-9][0-9] [0-9:.]+ ` +
		`[A-Z][A-Z0-9_+:-]*$`,
)

type Inventory struct {
	All InventoryGroup `yaml:"all"`
}

type InventoryGroup struct {
	Hosts    map[string]InventoryHost  `yaml:"hosts"`
	Children map[string]InventoryGroup `yaml:"children"`
}

type InventoryHost struct {
	AnsibleHost string `yaml:"ansible_host"`
}

type runConfig struct {
	LabPath       string
	OutDir        string
	InventoryPath string
	Only          string
	Backup        bool
	Restore       bool
	SkipHealth    bool
	Debug         bool
	Timeout       time.Duration
}

type nodeOperation func(node NodeInfo, outDir string, creds map[string]Creds) error

func main() {
	cfg := parseRunConfig()
	configureLogging(cfg.Debug)
	opTimeout = cfg.Timeout

	if err := validateMode(cfg.Backup, cfg.Restore); err != nil {
		exitWithUsage(err)
	}

	if err := run(cfg); err != nil {
		fatalf("%v", err)
	}
}

func parseRunConfig() runConfig {
	labPath := flag.String("lab", "lab.yml", "Containerlab topology file")
	outDir := flag.String("out", "mv-lab-config", "Output directory for configs")
	inventoryPath := flag.String("inventory", "", "Optional path to containerlab ansible-inventory.yml")
	backup := flag.Bool("backup", false, "Run backup")
	restore := flag.Bool("restore", false, "Run restore")
	skipHealth := flag.Bool("skip-health", false, "Skip docker health check")
	timeout := flag.Duration("timeout", defaultOpTimeout, "Scrapli operation timeout (e.g. 30s, 2m)")
	debug := flag.Bool("debug", false, "Enable debug logging (includes scrapli debug output)")
	only := flag.String("only", "", "Comma-separated node names to target (e.g. R01-nokia,R04-nokia)")
	flag.Parse()
	return runConfig{
		LabPath:       *labPath,
		OutDir:        *outDir,
		InventoryPath: *inventoryPath,
		Only:          *only,
		Backup:        *backup,
		Restore:       *restore,
		SkipHealth:    *skipHealth,
		Debug:         *debug,
		Timeout:       *timeout,
	}
}

func configureLogging(debug bool) {
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		l, err := scraplilogging.NewInstance(
			scraplilogging.WithLevel("debug"),
			scraplilogging.WithLogger(log.Print),
		)
		if err != nil {
			logrus.Warnf("failed to enable scrapli debug logger: %v", err)
		} else {
			scrapliLogger = l
		}
	}
}

func validateMode(backup, restore bool) error {
	if (backup && restore) || (!backup && !restore) {
		return errors.New("select exactly one of --backup or --restore")
	}
	return nil
}

func run(cfg runConfig) error {
	lab, nodes, err := loadNodes(cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output dir %q: %w", cfg.OutDir, err)
	}

	if !cfg.SkipHealth {
		ok, healthErr := allNodesHealthy(lab.Name, nodes)
		if healthErr != nil {
			printf("Health check warning: %v", healthErr)
		}
		if !ok {
			return errors.New("not all nodes are healthy; aborting")
		}
	}
	creds := credentialsFromEnv()
	if cfg.Backup {
		printf("Starting backup...")
		processNodes("backup", nodes, cfg.OutDir, creds, backupNode)
		return nil
	}

	printf("Starting restore...")
	processNodes("restore", nodes, cfg.OutDir, creds, restoreNode)
	return nil
}

func loadNodes(cfg runConfig) (Lab, []NodeInfo, error) {
	lab, err := readLab(cfg.LabPath)
	if err != nil {
		return Lab{}, nil, fmt.Errorf("failed to read lab file: %w", err)
	}

	inventoryHosts := map[string]string(nil)
	if invPath := resolveInventoryPath(cfg.InventoryPath, cfg.LabPath, lab.Name); invPath != "" {
		hosts, invErr := readInventoryHosts(invPath)
		if invErr != nil {
			printf("Inventory warning: failed to read %s: %v", invPath, invErr)
		} else {
			inventoryHosts = hosts
		}
	}

	nodes, err := nodesFromLab(lab, inventoryHosts)
	if err != nil {
		return Lab{}, nil, fmt.Errorf("failed to parse nodes: %w", err)
	}
	if cfg.Only == "" {
		return lab, nodes, nil
	}

	nodes, err = filterNodes(nodes, cfg.Only)
	if err != nil {
		return Lab{}, nil, fmt.Errorf("failed to apply --only filter: %w", err)
	}
	return lab, nodes, nil
}

func credentialsFromEnv() map[string]Creds {
	return map[string]Creds{
		"vr-xrv9k": {
			User: getEnv("CISCO_USERNAME", "clab"),
			Pass: getEnv("CISCO_PASSWORD", "clab@123"),
		},
		"vr-vmx": {
			User: getEnv("JUNIPER_USERNAME", "admin"),
			Pass: getEnv("JUNIPER_PASSWORD", "admin@123"),
		},
		"vr-sros": {
			User: getEnv("NOKIA_SROS_USERNAME", "admin"),
			Pass: getEnv("NOKIA_SROS_PASSWORD", "admin"),
		},
		"srl": {
			User: getEnv("NOKIA_SRL_USERNAME", "admin"),
			Pass: getEnv("NOKIA_SRL_PASSWORD", "NokiaSrl1!"),
		},
	}
}

func processNodes(action string, nodes []NodeInfo, outDir string, creds map[string]Creds, op nodeOperation) {
	actionTitle := strings.ToUpper(action[:1]) + action[1:]
	for _, node := range nodes {
		err := retry(fmt.Sprintf("%s %s", action, node.Name), func() error {
			return op(node, outDir, creds)
		})
		if err != nil {
			if errors.Is(err, errUnsupportedKind) {
				printf("Skipping %s (%s): %v", node.Name, node.Host, err)
				continue
			}
			printf("%s failed for %s (%s): %v", actionTitle, node.Name, node.Host, err)
			logStatus(outDir, fmt.Sprintf("%s: %s failed: %v", node.Name, action, err))
			continue
		}
		logStatus(outDir, fmt.Sprintf("%s: %s successful", node.Name, action))
	}
}

func exitWithUsage(err error) {
	if err != nil {
		logrus.Error(err)
	}
	logrus.Info("Usage:")
	logrus.Info("  --backup  Run backups")
	logrus.Info("  --restore Run restores")
	os.Exit(2)
}

func fatalf(format string, args ...any) {
	logrus.Fatalf(format, args...)
}

func printf(format string, args ...any) {
	logrus.Infof(format, args...)
}

func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}

func closeWithDebug(name string, closer io.Closer) {
	if closer == nil {
		return
	}
	if err := closer.Close(); err != nil {
		logrus.Debugf("failed to close %s: %v", name, err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func readLab(path string) (Lab, error) {
	var lab Lab
	data, err := os.ReadFile(path)
	if err != nil {
		return lab, wrapErr(fmt.Sprintf("read lab file %q", path), err)
	}
	if err := yaml.Unmarshal(data, &lab); err != nil {
		return lab, wrapErr("parse lab yaml", err)
	}
	return lab, nil
}

func nodesFromLab(lab Lab, inventoryHosts map[string]string) ([]NodeInfo, error) {
	if len(lab.Topology.Nodes) == 0 {
		return nil, errors.New("no nodes found in topology")
	}

	nodes := make([]NodeInfo, 0, len(lab.Topology.Nodes))
	for name, node := range lab.Topology.Nodes {
		if node.Kind == "" {
			printf("Skipping node %s: missing kind", name)
			continue
		}
		kind := normalizeKind(node.Kind)
		host := resolveNodeHost(name, node, lab.Name, inventoryHosts)
		if host == "" {
			printf("Skipping node %s: missing mgmt-ipv4/ansible_host", name)
			continue
		}
		nodes = append(nodes, NodeInfo{
			Name: name,
			Kind: kind,
			Host: host,
		})
	}

	if len(nodes) == 0 {
		return nil, errors.New("no nodes with management address found")
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Name < nodes[j].Name
	})
	return nodes, nil
}

func resolveNodeHost(name string, node Node, labName string, inventoryHosts map[string]string) string {
	host := normalizeIP(node.MgmtIPv4)
	if host != "" || len(inventoryHosts) == 0 {
		return host
	}
	if invHost, ok := inventoryHosts[name]; ok {
		return normalizeIP(invHost)
	}
	if labName == "" {
		return ""
	}
	clabName := fmt.Sprintf("clab-%s-%s", labName, name)
	if invHost, ok := inventoryHosts[clabName]; ok {
		return normalizeIP(invHost)
	}
	return ""
}

func filterNodes(nodes []NodeInfo, only string) ([]NodeInfo, error) {
	raw := strings.Split(only, ",")
	allowed := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		name := strings.TrimSpace(entry)
		if name == "" {
			continue
		}
		allowed[name] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no valid node names provided")
	}

	filtered := make([]NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		if _, ok := allowed[node.Name]; ok {
			filtered = append(filtered, node)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no nodes matched --only=%q", only)
	}
	return filtered, nil
}

func retry(action string, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= retryAttempts; attempt++ {
		err := fn()
		if err == nil || errors.Is(err, errUnsupportedKind) {
			return err
		}
		lastErr = err
		if attempt < retryAttempts {
			logrus.Warnf("%s attempt %d/%d failed: %v; retrying in %s", action, attempt, retryAttempts, err, retryDelay)
			time.Sleep(retryDelay)
		}
	}
	return lastErr
}

func normalizeIP(ip string) string {
	if idx := strings.Index(ip, "/"); idx != -1 {
		return ip[:idx]
	}
	return ip
}

func normalizeKind(kind string) string {
	switch kind {
	case "cisco_xrv9k":
		return "vr-xrv9k"
	case "juniper_vmx":
		return "vr-vmx"
	case "nokia_sros":
		return "vr-sros"
	case "nokia_srsim":
		return "vr-sros"
	case "nokia_srlinux":
		return "srl"
	default:
		return kind
	}
}

func resolveInventoryPath(flagValue, labPath, labName string) string {
	if flagValue != "" {
		return flagValue
	}
	if labName == "" {
		return ""
	}
	dir := filepath.Dir(labPath)
	candidate := filepath.Join(dir, fmt.Sprintf("clab-%s", labName), "ansible-inventory.yml")
	if fileExists(candidate) {
		return candidate
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readInventoryHosts(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapErr(fmt.Sprintf("read inventory file %q", path), err)
	}
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, wrapErr("parse inventory yaml", err)
	}
	hosts := make(map[string]string)
	flattenHosts(inv.All, hosts)
	return hosts, nil
}

func flattenHosts(group InventoryGroup, hosts map[string]string) {
	for name, host := range group.Hosts {
		if host.AnsibleHost != "" {
			hosts[name] = host.AnsibleHost
		}
	}
	for _, child := range group.Children {
		flattenHosts(child, hosts)
	}
}

func allNodesHealthy(labName string, nodes []NodeInfo) (bool, error) {
	if labName == "" {
		return true, errors.New("lab name not found in topology file")
	}

	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return true, fmt.Errorf("docker not found in PATH; skipping health check")
	}

	for _, node := range nodes {
		containerName := fmt.Sprintf("clab-%s-%s", labName, node.Name)
		cmd := exec.Command(dockerPath, "ps", "--filter", "name="+containerName, "--format", "{{.Status}}")
		out, err := cmd.Output()
		if err != nil {
			return false, fmt.Errorf("docker ps failed for %s: %w", containerName, err)
		}
		status := strings.TrimSpace(string(out))
		if status == "" {
			return false, fmt.Errorf("container %s not running", containerName)
		}
		if strings.Contains(status, "(unhealthy)") {
			return false, fmt.Errorf("container %s unhealthy", containerName)
		}
	}
	return true, nil
}

func platformForKind(kind string) (string, error) {
	switch kind {
	case "vr-xrv9k":
		return "cisco_iosxr", nil
	case "vr-vmx":
		return "juniper_junos", nil
	case "vr-sros":
		return "nokia_sros", nil
	case "srl":
		return "nokia_srl", nil
	default:
		return "", fmt.Errorf("%w %q", errUnsupportedKind, kind)
	}
}

func backupNode(node NodeInfo, outDir string, creds map[string]Creds) error {
	return runNodeOperation(node, outDir, creds, map[string]kindOperation{
		"vr-xrv9k": backupCisco,
		"vr-vmx":   backupJuniper,
		"vr-sros":  backupSros,
		"srl":      backupSrl,
	})
}

func restoreNode(node NodeInfo, outDir string, creds map[string]Creds) error {
	return runNodeOperation(node, outDir, creds, map[string]kindOperation{
		"vr-xrv9k": restoreCisco,
		"vr-vmx":   restoreJuniper,
		"vr-sros":  restoreSros,
		"srl":      restoreSrl,
	})
}

type kindOperation func(NodeInfo, string, string, Creds) error

func runNodeOperation(node NodeInfo, outDir string, creds map[string]Creds, operations map[string]kindOperation) error {
	platformName, err := platformForKind(node.Kind)
	if err != nil {
		return err
	}
	vendorCreds, ok := creds[node.Kind]
	if !ok {
		return fmt.Errorf("missing credentials for kind %q", node.Kind)
	}
	op, ok := operations[node.Kind]
	if !ok {
		return fmt.Errorf("%w %q", errUnsupportedKind, node.Kind)
	}
	return op(node, outDir, platformName, vendorCreds)
}

func connect(platformName, host string, creds Creds) (*network.Driver, error) {
	return connectWithOptions(platformName, host, creds, nil)
}

func connectWithOptions(platformName, host string, creds Creds, extra []util.Option) (*network.Driver, error) {
	options := []util.Option{
		driveroptions.WithAuthUsername(creds.User),
		driveroptions.WithAuthPassword(creds.Pass),
		driveroptions.WithAuthNoStrictKey(),
		driveroptions.WithTransportType(transport.StandardTransport),
		driveroptions.WithTimeoutOps(opTimeout),
	}
	if len(extra) > 0 {
		options = append(options, extra...)
	}
	if platformName == "nokia_sros" {
		options = append(options,
			driveroptions.WithPromptPattern(srosPromptPattern()),
			driveroptions.WithPrivilegeLevels(srosPrivilegeLevels()),
			driveroptions.WithDefaultDesiredPriv("exec"),
		)
	}
	if scrapliLogger != nil {
		options = append(options, driveroptions.WithLogger(scrapliLogger))
	}
	p, err := platform.NewPlatform(platformName, host, options...)
	if err != nil {
		return nil, wrapErr("create platform", err)
	}
	driver, err := p.GetNetworkDriver()
	if err != nil {
		return nil, wrapErr("get network driver", err)
	}
	if err := driver.Open(); err != nil {
		return nil, wrapErr("open network driver", err)
	}
	if platformName == "nokia_sros" {
		driver.UpdatePrivileges()
	}
	return driver, nil
}

func connectCisco(host string, creds Creds) (*network.Driver, error) {
	// First try default crypto; some XR builds drop connections if weak algos are offered.
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		defaultCiphers, defaultKexs := sshDefaults()
		logrus.Debugf("cisco iosxr ssh defaults: kex=%v ciphers=%v", defaultKexs, defaultCiphers)
	}
	driver, err := connectCiscoWithRetry("defaults", host, creds, nil)
	if err == nil {
		return driver, nil
	}
	if !isSSHHandshakeErr(err) {
		return nil, err
	}
	logrus.Warnf("cisco iosxr ssh handshake failed with defaults: %v; retrying with legacy ciphers/kex", err)
	legacyCiphers, legacyKexs := ciscoLegacySSHLists()
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.Debugf("cisco iosxr ssh legacy+defaults: kex=%v ciphers=%v", legacyKexs, legacyCiphers)
	}
	driver, err = connectCiscoWithRetry("legacy crypto", host, creds, ciscoLegacySSHOptions())
	if err == nil {
		return driver, nil
	}
	if !isSSHHandshakeErr(err) || !sshBinaryAvailable() {
		return nil, err
	}
	logrus.Warnf("cisco iosxr ssh handshake failed with legacy crypto: %v; retrying with system transport", err)
	driver, err = connectCiscoWithRetry("system transport", host, creds, ciscoSystemSSHOptions())
	if err == nil {
		return driver, nil
	}
	return nil, err
}

func connectCiscoWithRetry(mode, host string, creds Creds, extra []util.Option) (*network.Driver, error) {
	var lastErr error
	for attempt := 1; attempt <= ciscoHandshakeAttempts; attempt++ {
		driver, err := connectWithOptions("cisco_iosxr", host, creds, extra)
		if err == nil {
			return driver, nil
		}
		lastErr = err
		if !isSSHHandshakeErr(err) {
			return nil, err
		}
		if attempt < ciscoHandshakeAttempts {
			logrus.Warnf(
				"cisco iosxr %s handshake attempt %d/%d failed: %v; retrying in %s",
				mode, attempt, ciscoHandshakeAttempts, err, ciscoHandshakeRetryDelay,
			)
			time.Sleep(ciscoHandshakeRetryDelay)
		}
	}
	return nil, lastErr
}

func ciscoLegacySSHOptions() []util.Option {
	ciphers, kexs := ciscoLegacySSHLists()
	return []util.Option{
		driveroptions.WithStandardTransportExtraKexs(kexs),
		driveroptions.WithStandardTransportExtraCiphers(ciphers),
	}
}

func ciscoSystemSSHOptions() []util.Option {
	options := []util.Option{
		driveroptions.WithTransportType(transport.SystemTransport),
		driveroptions.WithSystemTransportOpenArgs([]string{
			"-tt",
			"-o", "PreferredAuthentications=password",
			"-o", "PubkeyAuthentication=no",
		}),
	}
	if cfg := strings.TrimSpace(os.Getenv("NCK_SSH_CONFIG")); cfg != "" {
		options = append(options, driveroptions.WithSSHConfigFile(cfg))
	} else {
		options = append(options, driveroptions.WithSSHConfigFileSystem())
	}
	return options
}

func ciscoLegacySSHLists() (ciphers []string, kexs []string) {
	defaultCiphers, defaultKexs := sshDefaults()
	// scrapligo "extra" lists replace defaults, so include defaults first.
	kexs = append(defaultKexs, []string{
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
	}...)
	ciphers = append(defaultCiphers, []string{
		"aes128-cbc",
		"aes256-cbc",
		"3des-cbc",
	}...)
	return ciphers, kexs
}

func isSSHHandshakeErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "handshake failed") ||
		strings.Contains(msg, "no common algorithm") ||
		strings.Contains(msg, "unable to negotiate") ||
		strings.Contains(msg, "kex_exchange_identification") ||
		strings.Contains(msg, "connection closed by remote host") ||
		strings.Contains(msg, "read /dev/ptmx: input/output error")
}

func sshBinaryAvailable() bool {
	_, err := exec.LookPath("ssh")
	if err != nil {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("ssh binary not found for system transport fallback: %v", err)
		}
		return false
	}
	return true
}

func sshDefaults() (ciphers []string, kexs []string) {
	var cfg ssh.Config
	cfg.SetDefaults()
	if len(cfg.Ciphers) > 0 {
		ciphers = append(ciphers, cfg.Ciphers...)
	}
	if len(cfg.KeyExchanges) > 0 {
		kexs = append(kexs, cfg.KeyExchanges...)
	}
	return ciphers, kexs
}

func srosPromptPattern() *regexp.Regexp {
	// Match either exec prompt or config-context + prompt (two-line).
	return regexp.MustCompile(
		`(?m)^(?:\*?\[(?:pr|ex):/configure\]\s*\n[A-Za-z]:[^\r\n]*[>#]\s*|` +
			`[A-Za-z]:[^\r\n]*[>#]\s*)$`,
	)
}

func srosPrivilegeLevels() map[string]*network.PrivilegeLevel {
	return map[string]*network.PrivilegeLevel{
		"exec": {
			Name:        "exec",
			Pattern:     `(?m)^[A-Za-z]:[^\r\n]*[>#]\s*$`,
			NotContains: []string{"[pr:/configure]", "[ex:/configure]"},
		},
		"configuration-private": {
			Name:         "configuration-private",
			Pattern:      `(?m)^\*?\[pr:/configure\]\s*\n[A-Za-z]:[^\r\n]*[>#]\s*$`,
			PreviousPriv: "exec",
			Deescalate:   "exit",
			Escalate:     "configure private",
		},
		"configuration-exclusive": {
			Name:         "configuration-exclusive",
			Pattern:      `(?m)^\*?\[ex:/configure\]\s*\n[A-Za-z]:[^\r\n]*[>#]\s*$`,
			PreviousPriv: "exec",
			Deescalate:   "exit",
			Escalate:     "configure exclusive",
		},
	}
}

func backupCisco(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Cisco XR %s (%s)...", node.Name, node.Host)
	conn, err := connectCisco(node.Host, creds)
	if err != nil {
		return wrapErr("connect to Cisco", err)
	}
	defer closeWithDebug("cisco connection", conn)

	_, _ = conn.SendCommand("terminal length 0")
	resp, err := conn.SendCommand("show running-config")
	if err != nil {
		return wrapErr("run 'show running-config'", err)
	}
	path := filepath.Join(outDir, node.Name+".txt")
	if err := os.WriteFile(path, []byte(resp.Result), 0o644); err != nil {
		return wrapErr(fmt.Sprintf("write backup file %q", path), err)
	}
	return nil
}

func backupJuniper(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Juniper vMX %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to Juniper", err)
	}
	defer closeWithDebug("juniper connection", conn)

	localPath := filepath.Join(outDir, node.Name+".txt")
	_, _ = conn.SendCommand("set cli screen-length 0")
	_, _ = conn.SendCommand("set cli screen-width 0")
	resp, err := conn.SendCommand("show configuration | display set")
	if err != nil {
		return wrapErr("run 'show configuration | display set'", err)
	}
	if err := os.WriteFile(localPath, []byte(resp.Result), 0o644); err != nil {
		return wrapErr(fmt.Sprintf("write backup file %q", localPath), err)
	}
	return nil
}

func backupSros(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Nokia SROS %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to SROS", err)
	}
	defer closeWithDebug("sros connection", conn)

	if _, err := conn.SendCommand("environment more false"); err != nil {
		return wrapErr("disable pager on SROS", err)
	}
	// Save to cf3 so SFTP can fetch from its root.
	saveCmd := fmt.Sprintf("admin save cf3:/%s.txt", node.Name)
	if _, err := conn.SendCommand(saveCmd); err != nil {
		return wrapErr("save running config on SROS", err)
	}
	time.Sleep(1 * time.Second)

	localPath := filepath.Join(outDir, node.Name+".txt")
	if err := srosDownload(node.Host, creds, node.Name+".txt", localPath); err == nil {
		return nil
	}

	// Fallback to streaming output if SFTP fails.
	resp, err := conn.SendCommand("admin show configuration running")
	if err != nil {
		return wrapErr("stream running config on SROS", err)
	}
	if err := os.WriteFile(localPath, []byte(resp.Result), 0o644); err != nil {
		return wrapErr(fmt.Sprintf("write backup file %q", localPath), err)
	}
	return nil
}

func backupSrl(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Nokia SRL %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to SRL", err)
	}
	defer closeWithDebug("srl connection", conn)

	cmd := fmt.Sprintf("save file %s.json from running", node.Name)
	if _, err := conn.SendCommand(cmd); err != nil {
		return wrapErr("save running config on SRL", err)
	}

	remotePath := fmt.Sprintf("/home/admin/%s.json", node.Name)
	localPath := filepath.Join(outDir, node.Name+".json")
	if err := sftpDownload(node.Host, creds, remotePath, localPath); err != nil {
		return wrapErr("download SRL config", err)
	}
	return nil
}

func restoreCisco(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Cisco XR %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	preparedPath, cleanup, err := prepareCiscoRestoreConfig(localPath)
	if err != nil {
		return wrapErr("prepare Cisco restore config", err)
	}
	defer cleanup()
	remotePath := fmt.Sprintf("/misc/scratch/%s.txt", node.Name)
	if err := sftpUpload(node.Host, creds, preparedPath, remotePath); err != nil {
		return wrapErr("upload Cisco restore config", err)
	}
	time.Sleep(ciscoRestorePostUploadWait)

	conn, err := connectCisco(node.Host, creds)
	if err != nil {
		return wrapErr("connect to Cisco", err)
	}
	defer closeWithDebug("cisco connection", conn)

	if _, err := conn.SendCommand("configure terminal"); err != nil {
		return wrapErr("enter Cisco configuration mode", err)
	}
	loadResp, err := conn.SendCommand(fmt.Sprintf("load %s", remotePath))
	if err != nil {
		return wrapErr("load Cisco restore config", err)
	}
	if strings.Contains(strings.ToLower(loadResp.Result), "syntax/authorization errors") {
		detailResp, detailErr := conn.SendCommand("show configuration failed load detail")
		_, _ = conn.SendCommand("abort")
		if detailErr != nil {
			return fmt.Errorf("cisco load failed with syntax/authorization errors (detail unavailable): %w", detailErr)
		}
		return fmt.Errorf(
			"cisco load failed with syntax/authorization errors:\n%s",
			strings.TrimSpace(detailResp.Result),
		)
	}

	if err := ciscoCommitReplace(conn); err != nil {
		return wrapErr("commit replace on Cisco", err)
	}
	return nil
}

func ciscoCommitReplace(conn *network.Driver) error {
	events := []*channel.SendInteractiveEvent{
		{
			ChannelInput:    "commit replace",
			ChannelResponse: `(?i)(do you wish to proceed\?.*\[no\]:|proceed.*\[no\]:|\[confirm\])`,
		},
		{
			ChannelInput:    "yes",
			ChannelResponse: `(?m)\(config\)#\s*$`,
		},
	}
	_, err := conn.SendInteractive(events, opoptions.WithPrivilegeLevel("configuration"))
	return wrapErr("send interactive commit replace", err)
}

func prepareCiscoRestoreConfig(localPath string) (preparedPath string, cleanup func(), err error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", nil, wrapErr(fmt.Sprintf("read restore file %q", localPath), err)
	}

	lines := strings.Split(string(data), "\n")
	sanitized := false
	for i := range lines {
		line := strings.TrimSuffix(lines[i], "\r")
		if ciscoTimestampLinePattern.MatchString(line) {
			lines[i] = "!! " + line
			sanitized = true
			continue
		}
		lines[i] = line
	}
	if !sanitized {
		return localPath, func() {}, nil
	}

	tmp, err := os.CreateTemp("", "nck-cisco-restore-*.txt")
	if err != nil {
		return "", nil, wrapErr("create temporary Cisco restore file", err)
	}

	joined := strings.Join(lines, "\n")
	if _, err := tmp.WriteString(joined); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, wrapErr("write temporary Cisco restore file", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, wrapErr("close temporary Cisco restore file", err)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.Debugf("sanitized Cisco restore config %s -> %s", localPath, tmp.Name())
	}
	return tmp.Name(), func() {
		_ = os.Remove(tmp.Name())
	}, nil
}

func restoreJuniper(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Juniper vMX %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	remotePath := fmt.Sprintf("/var/home/%s/%s.txt", creds.User, node.Name)
	if err := scpUpload(node.Host, creds, localPath, remotePath); err != nil {
		logrus.Warnf("juniper scp upload failed for %s (%s): %v; retrying with sftp", node.Name, node.Host, err)
		if sftpErr := sftpUpload(node.Host, creds, localPath, remotePath); sftpErr != nil {
			return fmt.Errorf(
				"juniper upload failed via scp and sftp: %w",
				errors.Join(err, sftpErr),
			)
		}
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to Juniper", err)
	}
	defer closeWithDebug("juniper connection", conn)

	if _, err := conn.SendCommand("configure private"); err != nil {
		return wrapErr("enter Juniper private config mode", err)
	}
	loadCmd, err := juniperLoadCommand(localPath, remotePath)
	if err != nil {
		return wrapErr("build Juniper load command", err)
	}
	if _, err := conn.SendCommand(loadCmd); err != nil {
		return wrapErr("load Juniper restore config", err)
	}
	_, _ = conn.SendCommand("show | compare | no-more")
	if _, err := conn.SendCommand("commit and-quit"); err != nil {
		return wrapErr("commit Juniper config", err)
	}
	_, _ = conn.SendCommand("exit")
	return nil
}

func restoreSros(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Nokia SROS %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	remoteFilename := node.Name + ".txt"

	if err := srosUpload(node.Host, creds, localPath, remoteFilename); err != nil {
		return wrapErr("upload SROS restore config", err)
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to SROS", err)
	}
	defer closeWithDebug("sros connection", conn)

	if _, err := conn.SendCommand("environment more false"); err != nil {
		return wrapErr("disable pager on SROS", err)
	}
	configs := []string{
		fmt.Sprintf("load full-replace cf3:%s", remoteFilename),
		"commit",
	}
	if _, err := conn.SendConfigs(configs, opoptions.WithPrivilegeLevel("configuration-private")); err != nil {
		return wrapErr("load and commit SROS config", err)
	}
	// Ignore logout errors; the device may close the session immediately.
	_, _ = conn.SendCommand("logout")
	return nil
}

func restoreSrl(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Nokia SRL %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".json")
	remotePath := fmt.Sprintf("/home/admin/%s.json", node.Name)
	if err := sftpUpload(node.Host, creds, localPath, remotePath); err != nil {
		return wrapErr("upload SRL restore config", err)
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return wrapErr("connect to SRL", err)
	}
	defer closeWithDebug("srl connection", conn)

	if _, err := conn.SendCommand("enter candidate"); err != nil {
		return wrapErr("enter SRL candidate mode", err)
	}
	if _, err := conn.SendCommand(fmt.Sprintf("load file %s.json auto-commit", node.Name)); err != nil {
		return wrapErr("load SRL restore config", err)
	}
	_, err = conn.SendCommand("exit all")
	return wrapErr("exit SRL session", err)
}

func newSSHClientConfig(creds Creds) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            creds.User,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
}

func sftpConnect(host string, creds Creds) (*sftp.Client, *ssh.Client, error) {
	cfg := newSSHClientConfig(creds)
	conn, err := ssh.Dial("tcp", host+":22", cfg)
	if err != nil {
		return nil, nil, wrapErr("dial ssh for sftp", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		closeWithDebug("sftp ssh connection", conn)
		return nil, nil, wrapErr("create sftp client", err)
	}
	return client, conn, nil
}

func sftpDownload(host string, creds Creds, remotePath, localPath string) error {
	client, conn, err := sftpConnect(host, creds)
	if err != nil {
		return err
	}
	defer closeWithDebug("sftp ssh connection", conn)
	defer closeWithDebug("sftp client", client)

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return wrapErr(fmt.Sprintf("create local dir for %q", localPath), err)
	}

	src, err := client.Open(remotePath)
	if err != nil {
		return wrapErr(fmt.Sprintf("open remote file %q", remotePath), err)
	}
	defer closeWithDebug("sftp source file", src)

	dst, err := os.Create(localPath)
	if err != nil {
		return wrapErr(fmt.Sprintf("create local file %q", localPath), err)
	}
	defer closeWithDebug("sftp destination file", dst)

	if _, err := io.Copy(dst, src); err != nil {
		return wrapErr("copy sftp download content", err)
	}
	return nil
}

func sftpUpload(host string, creds Creds, localPath, remotePath string) error {
	client, conn, err := sftpConnect(host, creds)
	if err != nil {
		return err
	}
	defer closeWithDebug("sftp ssh connection", conn)
	defer closeWithDebug("sftp client", client)

	src, err := os.Open(localPath)
	if err != nil {
		return wrapErr(fmt.Sprintf("open local file %q", localPath), err)
	}
	defer closeWithDebug("sftp source file", src)

	dst, err := client.Create(remotePath)
	if err != nil {
		return wrapErr(fmt.Sprintf("create remote file %q", remotePath), err)
	}
	defer closeWithDebug("sftp destination file", dst)

	if _, err := io.Copy(dst, src); err != nil {
		return wrapErr("copy sftp upload content", err)
	}
	return nil
}

func scpUpload(host string, creds Creds, localPath, remotePath string) error {
	cfg := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	conn, err := ssh.Dial("tcp", host+":22", cfg)
	if err != nil {
		return wrapErr("dial ssh for scp", err)
	}
	defer closeWithDebug("scp ssh connection", conn)

	session, stdin, outReader, errReader, err := prepareSCPSession(conn)
	if err != nil {
		return err
	}
	defer closeWithDebug("scp ssh session", session)

	src, size, err := openSCPSource(localPath)
	if err != nil {
		return err
	}
	defer closeWithDebug("scp source file", src)

	if err := session.Start(fmt.Sprintf("scp -t %s", remotePath)); err != nil {
		return wrapErr("start scp session", err)
	}
	if err := scpSendFile(stdin, src, size, filepath.Base(remotePath), outReader, errReader); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return wrapErr("close scp stdin", err)
	}
	if err := session.Wait(); err != nil {
		return wrapErr("wait for scp session", err)
	}
	return nil
}

func prepareSCPSession(conn *ssh.Client) (*ssh.Session, io.WriteCloser, *bufio.Reader, *bufio.Reader, error) {
	session, err := conn.NewSession()
	if err != nil {
		return nil, nil, nil, nil, wrapErr("create ssh session for scp", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		closeWithDebug("scp ssh session", session)
		return nil, nil, nil, nil, wrapErr("open scp stdin pipe", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		closeWithDebug("scp ssh session", session)
		return nil, nil, nil, nil, wrapErr("open scp stdout pipe", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		closeWithDebug("scp ssh session", session)
		return nil, nil, nil, nil, wrapErr("open scp stderr pipe", err)
	}
	return session, stdin, bufio.NewReader(stdout), bufio.NewReader(stderr), nil
}

func openSCPSource(localPath string) (*os.File, int64, error) {
	src, err := os.Open(localPath)
	if err != nil {
		return nil, 0, wrapErr(fmt.Sprintf("open local file %q for scp", localPath), err)
	}
	info, err := src.Stat()
	if err != nil {
		closeWithDebug("scp source file", src)
		return nil, 0, wrapErr("stat local file for scp", err)
	}
	return src, info.Size(), nil
}

func scpSendFile(
	stdin io.Writer,
	src io.Reader,
	size int64,
	remoteBase string,
	outReader, errReader *bufio.Reader,
) error {
	if err := scpReadAck(outReader, errReader); err != nil {
		return wrapErr("read initial scp ack", err)
	}
	if _, err := fmt.Fprintf(stdin, "C0644 %d %s\n", size, remoteBase); err != nil {
		return wrapErr("send scp file metadata", err)
	}
	if err := scpReadAck(outReader, errReader); err != nil {
		return wrapErr("read scp metadata ack", err)
	}
	if _, err := io.Copy(stdin, src); err != nil {
		return wrapErr("stream file content over scp", err)
	}
	if _, err := stdin.Write([]byte{0}); err != nil {
		return wrapErr("send scp end-of-file marker", err)
	}
	if err := scpReadAck(outReader, errReader); err != nil {
		return wrapErr("read final scp ack", err)
	}
	return nil
}

func scpReadAck(outReader, errReader *bufio.Reader) error {
	code, err := outReader.ReadByte()
	if err != nil {
		return wrapErr("read scp ack byte", err)
	}
	switch code {
	case 0:
		return nil
	case 1, 2:
		msg, _ := outReader.ReadString('\n')
		msg = strings.TrimSpace(msg)
		if msg == "" && errReader != nil && errReader.Buffered() > 0 {
			errMsg, _ := errReader.ReadString('\n')
			msg = strings.TrimSpace(errMsg)
		}
		if msg == "" {
			msg = fmt.Sprintf("scp remote error (code %d)", code)
		}
		return errors.New(msg)
	default:
		return fmt.Errorf("unexpected scp ack byte: %d", code)
	}
}

func juniperLoadCommand(localPath, remotePath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", wrapErr(fmt.Sprintf("open Juniper restore file %q", localPath), err)
	}
	defer closeWithDebug("juniper restore file", f)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "set ") {
			return fmt.Sprintf("load set %s", remotePath), nil
		}
		return fmt.Sprintf("load override %s", remotePath), nil
	}
	if err := scanner.Err(); err != nil {
		return "", wrapErr("scan Juniper restore file", err)
	}
	return fmt.Sprintf("load override %s", remotePath), nil
}

func srosDownload(host string, creds Creds, filename, localPath string) error {
	paths := []string{
		filename,
		"/" + filename,
		"cf3:/" + filename,
		"cf3:" + filename,
		"/cf3/" + filename,
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		for _, remote := range paths {
			err := sftpDownload(host, creds, remote, localPath)
			if err == nil {
				return nil
			}
			lastErr = err
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("sros download failed: %w", lastErr)
}

func srosUpload(host string, creds Creds, localPath, filename string) error {
	paths := []string{
		filename,
		"/" + filename,
		"cf3:/" + filename,
		"cf3:" + filename,
		"/cf3/" + filename,
	}
	var lastErr error
	for _, remote := range paths {
		err := sftpUpload(host, creds, localPath, remote)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("sros upload failed: %w", lastErr)
}

func logStatus(outDir, message string) {
	path := filepath.Join(outDir, "status.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer closeWithDebug("status log file", f)

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	if _, err := fmt.Fprintf(f, "%s - %s\n", timestamp, message); err != nil {
		logrus.Debugf("failed writing status log %q: %v", path, err)
	}
}
