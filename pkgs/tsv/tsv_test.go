package tsv

import "testing"

func TestValidate_MoreCases(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		desc  string
		input string
		want  bool
	}{
		{
			desc: "direct select with >= ago()",
			input: `
SELECT *
FROM mydb.sensors
WHERE time >= ago(15m)`,
			want: true,
		},
		{
			desc: "direct select missing WHERE",
			input: `
SELECT *
FROM mydb.sensors`,
			want: false,
		},
		{
			desc: "WHERE present but no time predicate",
			input: `
SELECT *
FROM mydb.sensors
WHERE measure_name = 'cpu'`,
			want: false,
		},
		{
			desc: "BETWEEN with now()",
			input: `
SELECT *
FROM mydb.sensors
WHERE time BETWEEN ago(1d) AND now()`,
			want: true,
		},
		{
			desc: "aggregation with GROUP BY and time filter",
			input: `
SELECT measure_name, avg(measure_value::double) AS v
FROM mydb.sensors
WHERE time > ago(1h)
GROUP BY measure_name`,
			want: true,
		},
		{
			desc: "JOIN with time filter in WHERE",
			input: `
SELECT *
FROM mydb.s1
JOIN mydb.s2 ON s1.device = s2.device
WHERE time >= ago(2h)`,
			want: true,
		},
		{
			desc: "JOIN without time filter",
			input: `
SELECT *
FROM mydb.s1
JOIN mydb.s2 ON s1.device = s2.device
WHERE s1.device <> ''`,
			want: false,
		},
		{
			desc: "CTEs (both sources time-filtered)",
			input: `
WITH a AS (
  SELECT * FROM mydb.s1
  WHERE time >= ago(1h)
),
b AS (
  SELECT * FROM mydb.s2
  WHERE time > ago(2h)
)
SELECT *
FROM a
JOIN b ON a.device = b.device`,
			want: true,
		},
		{
			desc: "CTEs (one source missing time filter)",
			input: `
WITH a AS (
  SELECT * FROM mydb.s1
),
b AS (
  SELECT * FROM mydb.s2
  WHERE time > ago(2h)
)
SELECT *
FROM a
JOIN b ON a.device = b.device`,
			want: false,
		},
		{
			desc: "derived table with inner time filter",
			input: `
SELECT x.*
FROM (
  SELECT *
  FROM mydb.s1
  WHERE time >= ago(5m)
) x
WHERE x.measure_value::double > 0`,
			want: true,
		},
		{
			desc: "derived table missing inner time filter",
			input: `
SELECT x.*
FROM (
  SELECT *
  FROM mydb.s1
) x`,
			want: false,
		},
		{
			desc: "UNION ALL with both sides filtered",
			input: `
SELECT *
FROM mydb.s1
WHERE time >= ago(1h)
UNION ALL
SELECT *
FROM mydb.s2
WHERE time >= ago(1h)`,
			want: true,
		},
		{
			desc: "UNION ALL with one side missing time filter",
			input: `
SELECT *
FROM mydb.s1
WHERE time >= ago(1h)
UNION ALL
SELECT *
FROM mydb.s2`,
			want: false,
		},
		{
			desc: "SELECT literal only (no FROM) is ignored",
			input: `
SELECT 1`,
			want: true,
		},
		{
			desc: "commented out time predicate should not count",
			input: `
SELECT *
FROM mydb.s1
WHERE /* time >= ago(1h) */ measure_name = 'x'`,
			want: false,
		},
		{
			desc: "measure_time comparison with function",
			input: `
SELECT *
FROM mydb.s1
WHERE measure_time >= from_iso8601_timestamp('2025-01-01T00:00:00Z')`,
			want: true,
		},
		{
			desc: "NOT BETWEEN on time",
			input: `
SELECT *
FROM mydb.s1
WHERE NOT time BETWEEN ago(1h) AND now()`,
			want: true,
		},
		{
			desc: "nested CTEs with inner-filtered source",
			input: `
WITH a AS (
  SELECT * FROM mydb.s1 WHERE time >= ago(1h)
),
z AS (
  WITH inner AS (
    SELECT * FROM mydb.s3 WHERE time >= ago(2h)
  )
  SELECT * FROM inner
)
SELECT * FROM a`,
			want: true,
		},
		{
			desc: "quoted db/table, unquoted time",
			input: `
SELECT *
FROM "mydb"."s1"
WHERE time >= ago(10m)`,
			want: true,
		},
		{
			desc: "time predicate placed in HAVING (invalid per rules)",
			input: `
SELECT device, max(time) AS t
FROM mydb.s1
GROUP BY device
HAVING max(time) >= ago(1h)`,
			want: false,
		},
		{
			desc:  "Free /data for devices (with \\n chars)",
			input: `SELECT\n  device AS \"Device\",\n  MIN(measure_value::double/1024/1024) AS \"Free /data [MB]\" \nFROM\n  \"ds-metric-forward\".\"metrics\"\nWHERE\n  time BETWEEN from_milliseconds(1755664656155) AND from_milliseconds(1755668256155)\n  AND measure_value::double < 1024000000\n  AND measure_name = 'gridx.ds.system.storage./data.available'\nGROUP BY\n  device\nORDER BY\n  device`,
			want:  true,
		},
		{
			desc:  "Free /data for devices (wich \\n chars, timefilter missing)",
			input: `SELECT\n  device AS \"Device\",\n  MIN(measure_value::double/1024/1024) AS \"Free /data [MB]\" \nFROM\n  \"ds-metric-forward\".\"metrics\"\nWHERE\n AND measure_value::double < 1024000000\n  AND measure_name = 'gridx.ds.system.storage./data.available'\nGROUP BY\n  device\nORDER BY\n  device`,
			want:  false,
		},
		{
			desc: "Free /data for devices (newlines)",
			input: `SELECT
  device AS "Device",
  MIN(measure_value::double/1024/1024) AS "Free /data [MB]" 
FROM
  $__database.$__table
WHERE
  $__timeFilter
  AND measure_value::double < 1024000000
  AND measure_name = '$__measure'
GROUP BY
  device
ORDER BY
  device`,
			want: true,
		},
		{
			desc: "Free /data for devices (newlines, time filter missing)",
			input: `SELECT
  device AS "Device",
  MIN(measure_value::double/1024/1024) AS "Free /data [MB]" 
FROM
  $__database.$__table
WHERE
  AND measure_value::double < 1024000000
  AND measure_name = '$__measure'
GROUP BY
  device
ORDER BY
  device`,
			want: false,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got, issues := Validate(tc.input, nil)
			if got != tc.want {
				t.Errorf("%s: want %v, got %v, issues: %+v", tc.desc, tc.want, got, issues)
			}
		})
	}
}
