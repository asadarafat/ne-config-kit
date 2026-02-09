package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/scrapli/scrapligo/driver/network"
	"github.com/scrapli/scrapligo/operation"
	"github.com/scrapli/scrapligo/options"
	"github.com/scrapli/scrapligo/platform"
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

func main() {
	labPath := flag.String("lab", "lab.yml", "Containerlab topology file")
	outDir := flag.String("out", "mv-lab-config", "Output directory for configs")
	backup := flag.Bool("backup", false, "Run backup")
	restore := flag.Bool("restore", false, "Run restore")
	skipHealth := flag.Bool("skip-health", false, "Skip docker health check")
	flag.Parse()

	if (*backup && *restore) || (!*backup && !*restore) {
		exitWithUsage(errors.New("select exactly one of --backup or --restore"))
	}

	lab, err := readLab(*labPath)
	if err != nil {
		fatalf("failed to read lab file: %v", err)
	}

	nodes, err := nodesFromLab(lab)
	if err != nil {
		fatalf("failed to parse nodes: %v", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("failed to create output dir: %v", err)
	}

	if !*skipHealth {
		ok, err := allNodesHealthy(lab.Name, nodes)
		if err != nil {
			printf("Health check warning: %v", err)
		}
		if !ok {
			fatalf("not all nodes are healthy; aborting")
		}
	}

	creds := map[string]Creds{
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

	if *backup {
		printf("Starting backup...")
		for _, node := range nodes {
			if err := backupNode(node, *outDir, creds); err != nil {
				printf("Backup failed for %s (%s): %v", node.Name, node.Host, err)
				logStatus(*outDir, fmt.Sprintf("%s: backup failed: %v", node.Name, err))
				continue
			}
			logStatus(*outDir, fmt.Sprintf("%s: backup successful", node.Name))
		}
		return
	}

	printf("Starting restore...")
	for _, node := range nodes {
		if err := restoreNode(node, *outDir, creds); err != nil {
			printf("Restore failed for %s (%s): %v", node.Name, node.Host, err)
			logStatus(*outDir, fmt.Sprintf("%s: restore failed: %v", node.Name, err))
			continue
		}
		logStatus(*outDir, fmt.Sprintf("%s: restore successful", node.Name))
	}
}

func exitWithUsage(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  --backup  Run backups")
	fmt.Fprintln(os.Stderr, "  --restore Run restores")
	os.Exit(2)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
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
		return lab, err
	}
	if err := yaml.Unmarshal(data, &lab); err != nil {
		return lab, err
	}
	return lab, nil
}

func nodesFromLab(lab Lab) ([]NodeInfo, error) {
	if len(lab.Topology.Nodes) == 0 {
		return nil, errors.New("no nodes found in topology")
	}

	nodes := make([]NodeInfo, 0, len(lab.Topology.Nodes))
	for name, node := range lab.Topology.Nodes {
		if node.Kind == "" || node.MgmtIPv4 == "" {
			continue
		}
		nodes = append(nodes, NodeInfo{
			Name: name,
			Kind: node.Kind,
			Host: normalizeIP(node.MgmtIPv4),
		})
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Name < nodes[j].Name
	})
	return nodes, nil
}

func normalizeIP(ip string) string {
	if idx := strings.Index(ip, "/"); idx != -1 {
		return ip[:idx]
	}
	return ip
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
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}

func backupNode(node NodeInfo, outDir string, creds map[string]Creds) error {
	platformName, err := platformForKind(node.Kind)
	if err != nil {
		return err
	}
	vendorCreds, ok := creds[node.Kind]
	if !ok {
		return fmt.Errorf("missing credentials for kind %q", node.Kind)
	}

	switch node.Kind {
	case "vr-xrv9k":
		return backupCisco(node, outDir, platformName, vendorCreds)
	case "vr-vmx":
		return backupJuniper(node, outDir, platformName, vendorCreds)
	case "vr-sros":
		return backupSros(node, outDir, platformName, vendorCreds)
	case "srl":
		return backupSrl(node, outDir, platformName, vendorCreds)
	default:
		return fmt.Errorf("unsupported kind %q", node.Kind)
	}
}

func restoreNode(node NodeInfo, outDir string, creds map[string]Creds) error {
	platformName, err := platformForKind(node.Kind)
	if err != nil {
		return err
	}
	vendorCreds, ok := creds[node.Kind]
	if !ok {
		return fmt.Errorf("missing credentials for kind %q", node.Kind)
	}

	switch node.Kind {
	case "vr-xrv9k":
		return restoreCisco(node, outDir, platformName, vendorCreds)
	case "vr-vmx":
		return restoreJuniper(node, outDir, platformName, vendorCreds)
	case "vr-sros":
		return restoreSros(node, outDir, platformName, vendorCreds)
	case "srl":
		return restoreSrl(node, outDir, platformName, vendorCreds)
	default:
		return fmt.Errorf("unsupported kind %q", node.Kind)
	}
}

func connect(platformName, host string, creds Creds) (*network.Driver, error) {
	p, err := platform.NewPlatform(
		platformName,
		host,
		options.WithAuthUsername(creds.User),
		options.WithAuthPassword(creds.Pass),
		options.WithAuthStrictKey(false),
	)
	if err != nil {
		return nil, err
	}
	driver, err := p.GetNetworkDriver()
	if err != nil {
		return nil, err
	}
	if err := driver.Open(); err != nil {
		return nil, err
	}
	return driver, nil
}

func backupCisco(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Cisco XR %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, _ = conn.SendCommand("terminal length 0")
	resp, err := conn.SendCommand("show running-config")
	if err != nil {
		return err
	}
	path := filepath.Join(outDir, node.Name+".txt")
	return os.WriteFile(path, []byte(resp.Result), 0o644)
}

func backupJuniper(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Juniper vMX %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	remotePath := fmt.Sprintf("/var/home/%s/%s.txt", creds.User, node.Name)
	cmd := fmt.Sprintf("show configuration | save %s", remotePath)
	if _, err := conn.SendCommand(cmd); err != nil {
		return err
	}

	localPath := filepath.Join(outDir, node.Name+".txt")
	return sftpDownload(node.Host, creds, remotePath, localPath)
}

func backupSros(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Nokia SROS %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.SendCommand("environment more false"); err != nil {
		return err
	}
	cmd := fmt.Sprintf("admin save %s.txt", node.Name)
	if _, err := conn.SendCommand(cmd); err != nil {
		return err
	}

	localPath := filepath.Join(outDir, node.Name+".txt")
	return srosDownload(node.Host, creds, node.Name+".txt", localPath)
}

func backupSrl(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Backing up Nokia SRL %s (%s)...", node.Name, node.Host)
	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	cmd := fmt.Sprintf("save file %s.json from running", node.Name)
	if _, err := conn.SendCommand(cmd); err != nil {
		return err
	}

	remotePath := fmt.Sprintf("/home/admin/%s.json", node.Name)
	localPath := filepath.Join(outDir, node.Name+".json")
	return sftpDownload(node.Host, creds, remotePath, localPath)
}

func restoreCisco(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Cisco XR %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	remotePath := fmt.Sprintf("/misc/scratch/%s.txt", node.Name)
	if err := sftpUpload(node.Host, creds, localPath, remotePath); err != nil {
		return err
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.SendCommand("configure terminal"); err != nil {
		return err
	}
	if _, err := conn.SendCommand(fmt.Sprintf("load %s", remotePath)); err != nil {
		return err
	}

	return ciscoCommitReplace(conn)
}

func ciscoCommitReplace(conn *network.Driver) error {
	events := []*operation.InteractiveEvent{
		operation.NewInteractiveEvent("commit replace", "(?i)(proceed|confirm|replace|yes/no|\[no\])"),
		operation.NewInteractiveEvent("yes", "(?i)(config|#)"),
	}
	_, err := conn.SendInteractive(events)
	return err
}

func restoreJuniper(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Juniper vMX %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	remotePath := fmt.Sprintf("/var/home/%s/%s.txt", creds.User, node.Name)
	if err := sftpUpload(node.Host, creds, localPath, remotePath); err != nil {
		return err
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.SendCommand("configure"); err != nil {
		return err
	}
	if _, err := conn.SendCommand(fmt.Sprintf("load replace %s", remotePath)); err != nil {
		return err
	}
	if _, err := conn.SendCommand("commit"); err != nil {
		return err
	}
	_, err = conn.SendCommand("exit")
	return err
}

func restoreSros(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Nokia SROS %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".txt")
	remoteFilename := node.Name + ".txt"

	if err := srosUpload(node.Host, creds, localPath, remoteFilename); err != nil {
		return err
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.SendCommand("configure exclusive"); err != nil {
		return err
	}
	if _, err := conn.SendCommand(fmt.Sprintf("load full-replace cf3:%s", remoteFilename)); err != nil {
		return err
	}
	if _, err := conn.SendCommand("commit"); err != nil {
		return err
	}
	_, err = conn.SendCommand("logout")
	return err
}

func restoreSrl(node NodeInfo, outDir, platformName string, creds Creds) error {
	printf("Restoring Nokia SRL %s (%s)...", node.Name, node.Host)
	localPath := filepath.Join(outDir, node.Name+".json")
	remotePath := fmt.Sprintf("/home/admin/%s.json", node.Name)
	if err := sftpUpload(node.Host, creds, localPath, remotePath); err != nil {
		return err
	}

	conn, err := connect(platformName, node.Host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.SendCommand("enter candidate"); err != nil {
		return err
	}
	if _, err := conn.SendCommand(fmt.Sprintf("load file %s.json auto-commit", node.Name)); err != nil {
		return err
	}
	_, err = conn.SendCommand("exit all")
	return err
}

func sftpConnect(host string, creds Creds) (*sftp.Client, *ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	conn, err := ssh.Dial("tcp", host+":22", cfg)
	if err != nil {
		return nil, nil, err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return client, conn, nil
}

func sftpDownload(host string, creds Creds, remotePath, localPath string) error {
	client, conn, err := sftpConnect(host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer client.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	src, err := client.Open(remotePath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func sftpUpload(host string, creds Creds, localPath, remotePath string) error {
	client, conn, err := sftpConnect(host, creds)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer client.Close()

	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := client.Create(remotePath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func srosDownload(host string, creds Creds, filename, localPath string) error {
	paths := []string{
		"cf3:/" + filename,
		"cf3:" + filename,
		"/cf3/" + filename,
	}
	var lastErr error
	for _, remote := range paths {
		err := sftpDownload(host, creds, remote, localPath)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("sros download failed: %w", lastErr)
}

func srosUpload(host string, creds Creds, localPath, filename string) error {
	paths := []string{
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
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	fmt.Fprintf(f, "%s - %s\n", timestamp, message)
}
