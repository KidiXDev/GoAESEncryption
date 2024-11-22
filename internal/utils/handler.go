package utils

import "fmt"

// CheckErr checks if an error is not nil and returns a formatted error message.
// If the error is nil, it returns nil.
//
// Parameters:
//   - msg: A string message to prepend to the error message.
//   - err: The error to check.
//
// Returns:
//   - An error with the formatted message if err is not nil, otherwise nil.
func CheckErr(msg string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}
