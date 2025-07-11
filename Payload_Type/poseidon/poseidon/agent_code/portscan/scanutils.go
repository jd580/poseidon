package portscan

import (
	// Standard
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	// External
	"golang.org/x/sync/semaphore"

	// Poseidon
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

type PortRange struct {
	Start int
	End   int
}

type host struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	PrettyName string `json:"pretty_name"`
	OpenPorts  []int  `json:"open_ports"`
	mutex      sync.Mutex
	lock       *semaphore.Weighted
}

type CIDR struct {
	Range string  `json:"range"`
	Hosts []*host `json:"hosts"`
}

// Validates that a new host can be created based on hostName
func NewHost(hostName string) (*host, error) {
	// chek if hostname is IP address
	if net.ParseIP(hostName) != nil {
		return &host{
			IP:         hostName,
			Hostname:   hostName,
			PrettyName: hostName,
			mutex:      sync.Mutex{},
			lock:       semaphore.NewWeighted(100), // yeah i hardcoded don't @me
		}, nil
	} else {
		// Try and lookup the hostname
		ips, err := net.LookupHost(hostName)
		if err != nil {
			return nil, err
		}
		hostStr := strings.Join(ips, "\n")
		return &host{
			IP:         ips[0],
			Hostname:   hostName,
			PrettyName: hostStr,
			mutex:      sync.Mutex{},
			lock:       semaphore.NewWeighted(100),
		}, nil
	}
}

func NewCIDR(cidrStr string) (*CIDR, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	var hosts []*host
	// Maybe single IP given?
	if err != nil {
		hostInst, err := NewHost(cidrStr)
		// Failed to parse the single ip. Fail out.
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, hostInst)
	} else {
		var ips []string
		for currentIP := ip.Mask(ipnet.Mask); ipnet.Contains(currentIP); inc(currentIP) {
			ips = append(ips, currentIP.String())
		}
		if len(ips) == 1 {
			hostInst, err := NewHost(ips[0])
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, hostInst)
		}
		// remove network address and broadcast address
		for i := 1; i < len(ips)-1; i++ {
			hostInst, err := NewHost(ips[i])
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, hostInst)
		}
	}
	return &CIDR{
		Range: cidrStr,
		Hosts: hosts,
	}, nil
}

// http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Scan a single port!
// export
func (server *host) ScanPort(port int, timeout time.Duration, job *structs.Job) error {
	var target string
	if strings.Contains(server.IP, ":") {
		target = fmt.Sprintf("[%s]:%d", server.IP, port)
	} else {
		target = fmt.Sprintf("%s:%d", server.IP, port)
	}
	if *job.Stop > 0 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", target, timeout)

	if conn != nil {
		conn.Close()
	}

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") || strings.Contains(err.Error(), "temporarily unavailable") {
			time.Sleep(timeout)
			return err
		}
		return nil
	}
	server.mutex.Lock()
	server.OpenPorts = append(server.OpenPorts, port)
	server.mutex.Unlock()
	return nil
}

// Scan a sequential range of ports
func (server *host) ScanPortRange(pr PortRange, timeout time.Duration, job *structs.Job) {
	wg := sync.WaitGroup{}

	for port := pr.Start; port <= pr.End; port++ {
		server.lock.Acquire(context.TODO(), 1)
		if *job.Stop > 0 {
			break
		}
		wg.Add(1)
		go func(port int, job *structs.Job) {
			defer server.lock.Release(1)
			defer wg.Done()
			for {
				// keep trying if we get an error
				if *job.Stop > 0 {
					return
				}
				err := server.ScanPort(port, timeout, job)
				if err == nil {
					return
				}
			}

		}(port, job)
	}
	wg.Wait()
}

// Scan a smattering of ports based on the slice.
func (server *host) ScanPortRanges(portList []PortRange, waitTime time.Duration, job *structs.Job) {
	// maybe start threading scan here
	// lim := Ulimit() / 2
	for i := 0; i < len(portList); i++ {
		if *job.Stop > 0 {
			return
		}
		server.ScanPortRange(portList[i], waitTime, job)
	}
}

func (cidrRange *CIDR) ScanHosts(portList []PortRange, waitTime time.Duration, job *structs.Job, throttler chan bool) {
	wg := sync.WaitGroup{}
	for i := 0; i < len(cidrRange.Hosts); i++ {
		throttler <- true // blocking call if we're full
		if *job.Stop > 0 {
			break
		}
		server := cidrRange.Hosts[i]
		wg.Add(1)
		go func(server *host, portList []PortRange, waitTime time.Duration, job *structs.Job) {
			defer func() {
				wg.Done()
				<-throttler // when we're done, take one off the queue so somebody else can run
			}()
			if *job.Stop > 0 {
				return
			}
			server.ScanPortRanges(portList, waitTime, job)
		}(server, portList, waitTime, job)
	}
	wg.Wait()
}

func (server *host) FormatOpenPorts() string {
	if len(server.OpenPorts) == 0 {
		return ""
	}
	result := ""
	result += fmt.Sprintf("Scan results for %s:\n", server.PrettyName)
	totalWhiteSpace := 6
	for i := 0; i < len(server.OpenPorts); i++ {
		result += fmt.Sprintf("\t%d%sopen\n", server.OpenPorts[i], strings.Repeat(" ", totalWhiteSpace-len(strconv.Itoa(server.OpenPorts[i]))))
	}
	result += fmt.Sprint("\n")
	return result
}

func (server *host) GreppableString() string {
	if len(server.OpenPorts) == 0 {
		return ""
	}
	totalWhiteSpace := 45 // arbitrary amt
	padding := totalWhiteSpace - len(server.PrettyName)
	if padding < 1 {
		padding = 1
	}
	portString := "("
	for i := 0; i < len(server.OpenPorts); i++ {
		addStr := fmt.Sprintf("%d/open", server.OpenPorts[i])
		if i != (len(server.OpenPorts) - 1) {
			addStr += ", "
		}
		portString += addStr
	}
	portString += ")"
	line := fmt.Sprintf("%s%s%s", server.PrettyName, strings.Repeat(" ", padding), portString)
	return line
}

func (cidrRange *CIDR) FormatOpenPorts() string {
	results := ""
	for i := 0; i < len(cidrRange.Hosts); i++ {
		results += cidrRange.Hosts[i].FormatOpenPorts()
	}
	return results
}
