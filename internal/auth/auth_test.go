package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid-key-123"},
			},
			expectedKey:   "valid-key-123",
			expectedError: "",
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "malformed authorization header - no ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed authorization header - only ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed authorization header - ApiKey without space",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed authorization header - ApiKey with extra parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey key1 key2"},
			},
			expectedKey:   "key1", // Only the first part after ApiKey should be returned
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if err != nil {
				if err.Error() != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
				}
			} else if tt.expectedError != "" {
				t.Errorf("expected error %q, got nil", tt.expectedError)
			}
		})
	}
}
