package proto

import (
	"encoding/json"
	"fmt"
)

// FindingTypeString returns a human-readable string representation of FindingType.
// This provides a custom format different from the default protobuf enum string.
func FindingTypeString(ft FindingType) string {
	switch ft {
	case FindingType_FINDING_TYPE_UNKNOWN:
		return "Unknown"
	case FindingType_FINDING_TYPE_SCA:
		return "SCA"
	case FindingType_FINDING_TYPE_SECRETS:
		return "Secrets"
	case FindingType_FINDING_TYPE_SAST:
		return "SAST"
	default:
		return "Unknown"
	}
}

// findingTypeFromString converts a custom string back to FindingType enum value.
func findingTypeFromString(s string) FindingType {
	switch s {
	case "Unknown":
		return FindingType_FINDING_TYPE_UNKNOWN
	case "SCA":
		return FindingType_FINDING_TYPE_SCA
	case "Secrets":
		return FindingType_FINDING_TYPE_SECRETS
	case "SAST":
		return FindingType_FINDING_TYPE_SAST
	default:
		return FindingType_FINDING_TYPE_UNKNOWN
	}
}

// MarshalJSON implements json.Marshaler for FindingType.
// This makes JSON marshal use the custom string format instead of the numeric value.
func (ft FindingType) MarshalJSON() ([]byte, error) {
	return json.Marshal(FindingTypeString(ft))
}

// UnmarshalJSON implements json.Unmarshaler for FindingType.
// This allows JSON to unmarshal from the custom string format back to the enum.
func (ft *FindingType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try to unmarshal as number for backward compatibility
		var n int32
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return fmt.Errorf("cannot unmarshal FindingType: %w", err)
		}
		*ft = FindingType(n)
		return nil
	}
	*ft = findingTypeFromString(s)
	return nil
}

// RiskSeverityString returns a human-readable string representation of RiskSeverity.
// This provides a custom format different from the default protobuf enum string.
func RiskSeverityString(rs RiskSeverity) string {
	switch rs {
	case RiskSeverity_RISK_SEVERITY_UNKNOWN:
		return "unknown"
	case RiskSeverity_RISK_SEVERITY_LOW:
		return "low"
	case RiskSeverity_RISK_SEVERITY_MEDIUM:
		return "medium"
	case RiskSeverity_RISK_SEVERITY_HIGH:
		return "high"
	case RiskSeverity_RISK_SEVERITY_CRITICAL:
		return "critical"
	default:
		return "unknown"
	}
}

// riskSeverityFromString converts a custom string back to RiskSeverity enum value.
func riskSeverityFromString(s string) RiskSeverity {
	switch s {
	case "unknown":
		return RiskSeverity_RISK_SEVERITY_UNKNOWN
	case "low":
		return RiskSeverity_RISK_SEVERITY_LOW
	case "medium":
		return RiskSeverity_RISK_SEVERITY_MEDIUM
	case "high":
		return RiskSeverity_RISK_SEVERITY_HIGH
	case "critical":
		return RiskSeverity_RISK_SEVERITY_CRITICAL
	default:
		return RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}

// MarshalJSON implements json.Marshaler for RiskSeverity.
// This makes JSON marshal use the custom string format instead of the numeric value.
func (rs RiskSeverity) MarshalJSON() ([]byte, error) {
	return json.Marshal(RiskSeverityString(rs))
}

// UnmarshalJSON implements json.Unmarshaler for RiskSeverity.
// This allows JSON to unmarshal from the custom string format back to the enum.
func (rs *RiskSeverity) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try to unmarshal as number for backward compatibility
		var n int32
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return fmt.Errorf("cannot unmarshal RiskSeverity: %w", err)
		}
		*rs = RiskSeverity(n)
		return nil
	}
	*rs = riskSeverityFromString(s)
	return nil
}
