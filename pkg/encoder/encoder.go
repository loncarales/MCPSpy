package encoder

// BytesToStr converts bytes to string, removing the trailing null bytes.
func BytesToStr(bytes []byte) string {
	var commStr string
	for i, b := range bytes[:] {
		if b == 0 {
			commStr = string(bytes[:i])
			break
		}
	}
	if commStr == "" {
		commStr = string(bytes[:])
	}
	return commStr
}
