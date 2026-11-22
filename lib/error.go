package lib

import "errors"

var (
	ErrDuplicatedConverter = errors.New("duplicated converter")
	ErrNotSupportedFormat  = errors.New("not supported format")
	ErrInvalidCIDR         = errors.New("invalid IP or CIDR")
	ErrInvalidDomain       = errors.New("invalid domain")
	ErrEntryNotFound       = errors.New("entry not found")
)
