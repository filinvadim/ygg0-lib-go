package ygg0_lib_go

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/mr-tron/base58/base58"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"suah.dev/protect"

	gologme "github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"github.com/yggdrasil-network/yggdrasil-go/src/tun"
)

type MeshLogger interface {
	Printf(s string, i ...interface{})
	Println(i ...interface{})
	Infof(s string, i ...interface{})
	Infoln(i ...interface{})
	Warnf(s string, i ...interface{})
	Warnln(i ...interface{})
	Errorf(s string, i ...interface{})
	Errorln(i ...interface{})
	Debugf(s string, i ...interface{})
	Debugln(i ...interface{})
	Traceln(i ...interface{})
}

type MeshRouter struct {
	ctx       context.Context
	core      *core.Core
	tun       *tun.TunAdapter
	multicast *multicast.Multicast
	humanID   string
}

type KeyBytes = config.KeyBytes

type Config struct {
	Logger           MeshLogger
	PrivateKey       KeyBytes
	PublicNodes      []string
	ListenAddrs      []string
	AllowedPubKeys   []string
	Certificate      *tls.Certificate
	AllowedIPs       *net.IPNet
	NodeInfoPrivacy  bool
	TunEnabled       bool
	MulticastEnabled bool
	InterfacePeers   map[string][]string
	NodeMetaData     map[string]interface{}
}

// NewMeshRouter function is responsible for configuring and starting Yggdrasil.
func NewMeshRouter(
	ctx context.Context,
	conf Config,
) (_ *MeshRouter, err error) {
	if err := protect.Unveil("/", "rwc"); err != nil {
		return nil, fmt.Errorf("unveil: / rwc: %v", err)
	}
	if err := protect.UnveilBlock(); err != nil {
		return nil, fmt.Errorf("unveil: %v", err)
	}

	if len(conf.PublicNodes) == 0 {
		return nil, fmt.Errorf("at least one public node is required")
	}
	if len(conf.ListenAddrs) == 0 {
		return nil, fmt.Errorf("at least one listen address is required")
	}

	if conf.Certificate == nil {
		ncfg := &config.NodeConfig{}
		if err := ncfg.GenerateSelfSignedCertificate(); err != nil {
			return nil, fmt.Errorf("mesh: generate self-signed certificate: %v", err)
		}
		conf.Certificate = ncfg.Certificate
	}
	if conf.AllowedIPs == nil {
		conf.AllowedIPs = &net.IPNet{
			IP:   net.ParseIP("200::"),
			Mask: net.CIDRMask(7, 128),
		}
	}

	n := &MeshRouter{ctx: ctx}

	options := []core.SetupOption{
		core.NodeInfo(conf.NodeMetaData),
		core.NodeInfoPrivacy(conf.NodeInfoPrivacy),
		core.PeerFilter(func(ip net.IP) bool {
			return conf.AllowedIPs.Contains(ip)
		}),
	}
	for _, addr := range conf.ListenAddrs {
		options = append(options, core.ListenAddress(addr))
	}
	for _, peer := range conf.PublicNodes {
		options = append(options, core.Peer{URI: peer})
	}
	for intf, peers := range conf.InterfacePeers {
		for _, peer := range peers {
			options = append(options, core.Peer{URI: peer, SourceInterface: intf})
		}
	}
	for _, allowed := range conf.AllowedPubKeys {
		k, err := hex.DecodeString(allowed)
		if err != nil {
			return nil, fmt.Errorf("mesh: hex: %v", err)
		}
		options = append(options, core.AllowedPublicKey(k[:]))
	}
	if n.core, err = core.New(conf.Certificate, conf.Logger, options...); err != nil {
		return nil, fmt.Errorf("mesh: core: %v", err)
	}

	// Set up the multicast module.
	if conf.MulticastEnabled {
		defaultMulticastInterfaces := []config.MulticastInterfaceConfig{
			{Regex: ".*", Beacon: true, Listen: true},
		}

		var options []multicast.SetupOption
		for _, intf := range defaultMulticastInterfaces {
			options = append(options, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}

		logme := gologme.New(os.Stdout, "multicast: ", gologme.LstdFlags)
		if n.multicast, err = multicast.New(n.core, logme, options...); err != nil {
			return nil, fmt.Errorf("mesh: multicast: %v", err)
		}
	}

	// Set up the TUN module.
	if conf.TunEnabled {
		ifName := "auto"
		ifMTU := 65535
		options := []tun.SetupOption{
			tun.InterfaceName(ifName),
			tun.InterfaceMTU(ifMTU),
		}
		if n.tun, err = tun.New(ipv6rwc.NewReadWriteCloser(n.core), conf.Logger, options...); err != nil {
			return nil, fmt.Errorf("mesh: TUN: %v", err)
		}
	}

	n.humanID = base58.Encode(n.core.GetSelf().Key)

	conf.Logger.Debugf(
		"MESH NETWORK LAYER INITIATED WITH ID %v AND ADDRESS %s\n",
		n.humanID, n.core.Address().String(),
	)
	return n, nil
}

func (mr *MeshRouter) HumanReadableID() string {
	return mr.humanID
}

type SelfInfo = core.SelfInfo

func (mr *MeshRouter) SelfInfo() SelfInfo {
	return mr.core.GetSelf()
}

func (mr *MeshRouter) PrivateKey() ed25519.PrivateKey {
	return mr.core.PrivateKey()
}

func (mr *MeshRouter) PublicKey() ed25519.PublicKey {
	return mr.core.PublicKey()
}

type PathEntryInfos = []core.PathEntryInfo

func (mr *MeshRouter) Paths() PathEntryInfos {
	return mr.core.GetPaths()
}

type PeerInfos = []core.PeerInfo

func (mr *MeshRouter) Peers() PeerInfos {
	return mr.core.GetPeers()
}

type SessionInfos = []core.SessionInfo

func (mr *MeshRouter) Sessions() SessionInfos {
	return mr.core.GetSessions()
}

func (mr *MeshRouter) CallPeer(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	return mr.core.CallPeer(u, "")
}

func (mr *MeshRouter) AddPeer(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	return mr.core.AddPeer(u, "")
}

func (mr *MeshRouter) RemovePeer(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	return mr.core.RemovePeer(u, "")
}

type Listener = *core.Listener

func (mr *MeshRouter) Listen(addr string) (Listener, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	return mr.core.Listen(u, "")
}

func (mr *MeshRouter) ListenLocal(addr string) (Listener, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	return mr.core.ListenLocal(u, "")
}

func (mr *MeshRouter) SetPathNotify(f func(key ed25519.PublicKey)) {
	mr.core.SetPathNotify(f)
}

func (mr *MeshRouter) LocalAddress() net.Addr {
	return mr.core.LocalAddr()
}

type TreeEntryInfos = []core.TreeEntryInfo

func (mr *MeshRouter) Tree() TreeEntryInfos {
	return mr.core.GetTree()
}

func (mr *MeshRouter) Address() net.IP {
	return mr.core.Address()
}

func (mr *MeshRouter) Subnet() net.IPNet {
	return mr.core.Subnet()
}

func (mr *MeshRouter) TunName() string {
	if mr.tun == nil {
		return ""
	}
	return mr.tun.Name()
}

func (mr *MeshRouter) TunIsStarted() bool {
	if mr.tun == nil {
		return false
	}
	return mr.tun.IsStarted()
}

func (mr *MeshRouter) MulticastIsStarted() bool {
	if mr.multicast == nil {
		return false
	}
	return mr.multicast.IsStarted()
}

func (mr *MeshRouter) MulticastInterfaces() map[string]net.Interface {
	if mr.multicast == nil {
		return nil
	}
	return mr.multicast.Interfaces()
}

func (mr *MeshRouter) AnnounceNow() {
	if mr.multicast == nil {
		return
	}
	mr.multicast.AnnounceNow()
}

func (mr *MeshRouter) Stop() {
	if mr == nil {
		return
	}

	promises := []string{"stdio", "cpath", "inet", "unix", "dns"}
	if len(mr.multicast.Interfaces()) > 0 {
		promises = append(promises, "mcast")
	}
	if err := protect.Pledge(strings.Join(promises, " ")); err != nil {
		panic(fmt.Sprintf("pledge: %v: %v", promises, err))
	}

	if mr.multicast != nil {
		_ = mr.multicast.Stop()
	}
	if mr.tun != nil {
		_ = mr.tun.Stop()
	}
	if mr.core != nil {
		mr.core.Stop()
	}
}
