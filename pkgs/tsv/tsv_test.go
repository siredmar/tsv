package tsv

import (
	"testing"
)

func TestBootConfUnmarshal(t *testing.T) {
	testcases := []struct {
		desc  string
		input string
		want  bool
	}{
		{
			desc: "valid input",
			input: `
  WITH base AS (
    SELECT * FROM "mydb"."sensors"
    WHERE time BETWEEN ago(1d) AND now()
  )
  SELECT measure_name, avg(measure_value::double) AS v
  FROM base
  GROUP BY measure_name`,
			want: true,
		},
		{
			desc: "time missing",
			input: `
  WITH base AS (
    SELECT * FROM "mydb"."sensors"
  )
  SELECT measure_name, avg(measure_value::double) AS v
  FROM base
  GROUP BY measure_name`,
			want: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			b, _ := Validate(tc.input, nil)
			if b == tc.want {
				t.Errorf("%s: want %v, got %v", tc.desc, tc.want, b)
			}
		})
	}
}
