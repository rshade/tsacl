// Package ipcalc provides policy-agnostic subnet arithmetic. It knows nothing
// about tsipam's registry, CLI, or Tailscale-specific concepts.
package ipcalc

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
)

const MaxMaterializedChildren = 65536

// ipv4In6PrefixBits is the length of the fixed ::ffff:0:0/96 mapping prefix
// that precedes the embedded IPv4 address in a 4-in-6 address.
const ipv4In6PrefixBits = 96

var ErrTooManyChildren = errors.New("ipcalc: split would produce too many children to materialize")

// Unmap4In6 rewrites an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) to its
// equivalent plain IPv4 prefix. ok is false if prefix is not a 4-in-6
// address, or if its bit length is too short to represent a valid IPv4
// prefix once the 96-bit mapping prefix is removed. A caller that supports
// IPv6 can preserve the original prefix when ok is false.
func Unmap4In6(prefix netip.Prefix) (netip.Prefix, bool) {
	addr := prefix.Addr()
	if !addr.Is4In6() || prefix.Bits() < ipv4In6PrefixBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-ipv4In6PrefixBits), true
}

// Split divides parent into equal-sized child prefixes of length targetBits.
// If targetBits is shorter than parent's own prefix length, or longer than
// the address family's bit length, Split returns an error. Split works for
// both IPv4 and IPv6 — family-specific restrictions belong to callers, not
// this function.
//
// If the number of children would exceed MaxMaterializedChildren, Split
// returns (nil, count, ErrTooManyChildren) — count is still the exact
// number (as [big.Int], since it can exceed uint64 range for IPv6 callers),
// so a caller can report it without enumerating.
func Split(parent netip.Prefix, targetBits int) ([]netip.Prefix, *big.Int, error) {
	if !parent.IsValid() {
		return nil, nil, errors.New("ipcalc: invalid parent prefix")
	}

	parent = parent.Masked()
	parentBits := parent.Bits()
	addrLen := parent.Addr().BitLen()

	if targetBits < parentBits {
		return nil, nil, fmt.Errorf("ipcalc: target prefix length /%d is shorter than parent /%d",
			targetBits, parentBits)
	}

	if targetBits > addrLen {
		return nil, nil, fmt.Errorf("ipcalc: target prefix length /%d exceeds address length /%d",
			targetBits, addrLen)
	}

	// Compute count as 2^(targetBits - parentBits)
	count := new(big.Int).Lsh(big.NewInt(1), uint(targetBits-parentBits))

	if count.Cmp(big.NewInt(MaxMaterializedChildren)) > 0 {
		return nil, count, ErrTooManyChildren
	}

	// Compute block size: 2^(addrLen - targetBits)
	blockSize := new(big.Int).Lsh(big.NewInt(1), uint(addrLen-targetBits))

	is4 := parent.Addr().Is4()
	n := count.Int64()
	children := make([]netip.Prefix, n)

	childAddr := addrToBigInt(parent.Addr())
	for i := range n {
		if i > 0 {
			childAddr.Add(childAddr, blockSize)
		}
		children[i] = netip.PrefixFrom(bigIntToAddr(childAddr, is4), targetBits)
	}

	return children, count, nil
}

func addrToBigInt(addr netip.Addr) *big.Int {
	return new(big.Int).SetBytes(addr.AsSlice())
}

func bigIntToAddr(n *big.Int, is4 bool) netip.Addr {
	byteLen := 16
	if is4 {
		byteLen = 4
	}
	buf := make([]byte, byteLen)
	n.FillBytes(buf)
	if is4 {
		return netip.AddrFrom4([4]byte(buf))
	}
	return netip.AddrFrom16([16]byte(buf))
}
