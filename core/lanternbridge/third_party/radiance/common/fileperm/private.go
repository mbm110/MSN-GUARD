package fileperm

import "os"

// Private is the mode for a file only its owner may read on every platform,
// including those where [File] is readable by others.
const Private os.FileMode = 0o600
