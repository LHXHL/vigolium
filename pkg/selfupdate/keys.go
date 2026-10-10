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
// These are PUBLIC keys and are meant to be published: they can only verify
// signatures, never create them. The matching secret keys are kept outside the
// repo (see `make release-sign`). Tests use their own key via
// Options.TrustedKeys; never put a test key in this list.
var trustedKeys = []string{
	"RWRFygL+4hNxGBX7o1N8ye9P76suTEmA/5TAoowxAPqN10HTS7maI6cQ",
	"RWROPwa0u8wc4KitxzSSYyuuaLsp7OkPlFt0cxcgJ6/zlAKTBmO4CWpT",
}

// ErrNoTrustedKeys means this build carries no usable release signing key.
var ErrNoTrustedKeys = errors.New("this build has no release signing key configured; " +
	"reinstall with the install script (https://vigolium.com/install.sh) instead")
