package main

import (
	"fmt"
	"testing"
	"time"
)

func TestProbeMobile(t *testing.T) {
	junk := `{"Jc":"7","Jmin":"66","Jmax":"112","S1":"46","S2":"75","S3":"19","S4":"22","H1":"100000-200000","H2":"300000-400000","H3":"500000-600000","H4":"700000-800000"}`
	rtt, err := probeRTT("138.124.124.203", 8443,
		"kvQ9Wf6nRCU549hwQZEOqkwIbZ0ZCJUBoLZvKjT+cuU=",
		"DrgKjEqZaPW+Wodw2Hl/b5Q9RME63kxPPSheVwSQhVw=",
		"",
		junk,
		5*time.Second,
	)
	fmt.Printf("mobile probe rtt=%v err=%v\n", rtt, err)
}
