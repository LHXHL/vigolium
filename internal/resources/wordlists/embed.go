package wordlists

import "embed"

// WordlistsFS holds the bundled wordlists. Large lists may ship gzip-compressed
// as NAME.txt.gz; read them through ReadList, which gunzips transparently, and
// materialize them through EnsureOnDisk, which writes the decompressed NAME.txt.
//
//go:embed *.txt *.list *.txt.gz
var WordlistsFS embed.FS
