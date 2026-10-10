package selfupdate

import "errors"

// trustedKeys are the minisign public keys allowed to sign a release's
// checksums.txt (the base64 line of `minisign.pub`, "RW…"). There are two
// slots so the signing key can rotate without stranding installed binaries:
//
//   - slot 0: the key `make release-sign` signs with today;
//   - slot 1: the next key. Ship it here at least one release before switching
//     the signer to it, then move it to slot 0 and add a new "next".
//
// TODO(release-key): both slots hold placeholders. Until the real public keys
// replace them, every verification fails closed with ErrNoTrustedKeys, so
// `vigolium update` installs nothing (`--check` still works, and install.sh
// stays the recovery path). Generate with `minisign -G -p vigolium.pub -s
// vigolium.key`, keep the secret key offline, and paste the second line of
// vigolium.pub here. Tests use their own key via Options.TrustedKeys; never
// put a test key in this list.
var trustedKeys = []string{
	"TODO-REPLACE-WITH-CURRENT-RELEASE-MINISIGN-PUBLIC-KEY",
	"TODO-REPLACE-WITH-NEXT-RELEASE-MINISIGN-PUBLIC-KEY",
}

// ErrNoTrustedKeys means this build carries no usable release signing key.
var ErrNoTrustedKeys = errors.New("this build has no release signing key configured; " +
	"reinstall with the install script (https://vigolium.com/install.sh) instead")

// TrustedKeysConfigured reports whether at least one built-in key slot holds a
// real public key.
func TrustedKeysConfigured() bool {
	for _, k := range trustedKeys {
		if _, err := parsePublicKey(k); err == nil {
			return true
		}
	}
	return false
}
