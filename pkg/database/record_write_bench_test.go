package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// newBenchIterationDB opens a store the caller closes itself, so a benchmark
// loop does not accumulate one live database per iteration.
func newBenchIterationDB(b *testing.B) *DB {
	b.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		b.Fatalf("open sqlite: %v", err)
	}
	// SQLite `:memory:` databases are per-connection, so pin to one connection.
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	db := &DB{DB: bun.NewDB(sqldb, sqlitedialect.New()), driver: "sqlite"}
	if err := db.CreateSchema(context.Background()); err != nil {
		b.Fatalf("create schema: %v", err)
	}
	return db
}

// benchPair builds one request/response pair with an HTML body of bodyLen bytes.
// HTML because that is the content type that triggers the title parse, i.e. the
// expensive shape the conversion path actually meets on a real scan.
func benchPair(i, bodyLen int) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET /path/%d HTTP/1.1\r\nHost: bench.example.com\r\nUser-Agent: bench\r\n\r\n", i)
	req, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		panic(err)
	}
	req = req.WithService(httpmsg.NewServiceSecure("bench.example.com", 443, true))

	body := "<html><head><title>Bench Page</title></head><body>" +
		strings.Repeat("content word ", bodyLen/13) + "</body></html>"
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
	return req.WithResponse(httpmsg.NewHttpResponse([]byte(rawResp)))
}

// BenchmarkFromHttpRequestResponse measures the full conversion — UUID, two
// SHA-256 passes, HTML title parse, word count, normalized body hash, parameter
// parse — across body sizes. This is the work RecordWriter.admit pays for EVERY
// record, including ones the dedup cache is about to discard.
func BenchmarkFromHttpRequestResponse(b *testing.B) {
	for _, bodyLen := range []int{1 << 10, 64 << 10, 512 << 10} {
		b.Run(fmt.Sprintf("body=%dKiB", bodyLen>>10), func(b *testing.B) {
			rr := benchPair(1, bodyLen)
			b.ReportAllocs()
			b.SetBytes(int64(len(rr.Response().Raw())))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rec := &HTTPRecord{}
				if err := rec.FromHttpRequestResponse(rr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRecordWriterAdmitDuplicate is the duplicate-heavy ingestion path:
// every Write after the first hits the in-memory dedup cache and is discarded.
// The cost that matters here is whatever admit does BEFORE consulting that cache.
func BenchmarkRecordWriterAdmitDuplicate(b *testing.B) {
	for _, bodyLen := range []int{1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("body=%dKiB", bodyLen>>10), func(b *testing.B) {
			db := newTestDB(b)
			repo := NewRepository(db)
			w := NewRecordWriter(repo, RecordWriterConfig{})
			defer w.Close()

			ctx := context.Background()
			rr := benchPair(1, bodyLen)

			// Prime the dedup cache so every timed iteration is a cache hit.
			if _, err := w.Write(ctx, rr, "bench", DefaultProjectUUID); err != nil {
				b.Fatalf("prime: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := w.Write(ctx, rr, "bench", DefaultProjectUUID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRecordWriterUniqueWrites is the counterpart: every record is new, so
// it pays conversion AND the insert. Kept alongside the duplicate benchmark
// because an optimization that helps duplicates must not tax unique rows.
// BatchSize=1 so each Write commits on its own, measuring conversion plus
// insert rather than any batching effect.
func BenchmarkRecordWriterUniqueWrites(b *testing.B) {
	db := newTestDB(b)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{
		BatchSize: 1,
	})
	defer w.Close()

	ctx := context.Background()
	// One unique pair per iteration, all built BEFORE the timer starts: building
	// them inside the loop would measure strings.Repeat and ParseRawRequest
	// instead of the conversion and insert this benchmark is about.
	pairs := make([]*httpmsg.HttpRequestResponse, b.N)
	for i := range pairs {
		pairs[i] = benchPair(i, 4<<10)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(ctx, pairs[i], "bench", DefaultProjectUUID); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSaveRecordBatch measures a bulk submission of the shape discovery
// hands the writer: one whole provenance group at once.
func BenchmarkSaveRecordBatch(b *testing.B) {
	for _, n := range []int{64, 512} {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			records := make([]*httpmsg.HttpRequestResponse, n)
			for j := range records {
				records[j] = benchPair(j, 4<<10)
			}

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// A fresh store per iteration, closed at the end of the SAME
				// iteration. Leaving them to b.Cleanup kept every iteration's
				// in-memory database live for the whole run, so GC pressure — and
				// with it the timed region — grew as the benchmark went on.
				db := newBenchIterationDB(b)
				w := NewRecordWriter(NewRepository(db), RecordWriterConfig{})
				b.StartTimer()

				if _, err := w.SaveRecordBatch(ctx, records, "bench", DefaultProjectUUID); err != nil {
					b.Fatal(err)
				}

				b.StopTimer()
				w.Close()
				_ = db.Close()
				b.StartTimer()
			}
		})
	}
}

// BenchmarkRecordWriterConcurrentWriters measures the shape a scan actually
// produces: N workers each blocking on their own Write, at the DEFAULT
// BatchSize.
//
// This is the case the other write benchmarks deliberately configure away.
// BenchmarkRecordWriterUniqueWrites sets BatchSize=1 so it can measure
// conversion and insert without the timer; that also hides the coupling this
// benchmark exists for. Write is admit-then-await, so a worker cannot enqueue
// its next row until the current one commits, which caps in-flight rows at the
// worker count - well under the default BatchSize of 128. The batch-full branch
// was therefore unreachable on any ordinary scan and every row waited out the
// flush ticker, at a cost paid per redirect hop because a hop's UUID is the next
// hop's parent.
//
// Reported per write.
// Before the flush loop drained what was already queued and committed it
// (darwin/arm64, in-memory SQLite, 2000 writes):
//
//	workers=1    49,994,022 ns/op -> 274,523 ns/op
//	workers=8     6,244,486 ns/op ->  92,613 ns/op
//	workers=40    1,247,306 ns/op ->  70,825 ns/op
//
// The old figures are the former 50ms flush interval divided by the worker
// count, to three digits - the signature of a batch that only ever flushed on
// the timer.
func BenchmarkRecordWriterConcurrentWriters(b *testing.B) {
	for _, workers := range []int{1, 8, 40} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			db := newTestDB(b)
			repo := NewRepository(db)
			// Default batching on purpose - the defaults are what a scan runs.
			w := NewRecordWriter(repo, RecordWriterConfig{})
			defer w.Close()

			ctx := context.Background()
			pairs := make([]*httpmsg.HttpRequestResponse, b.N)
			for i := range pairs {
				pairs[i] = benchPair(i, 4<<10)
			}

			var next atomic.Int64
			b.ReportAllocs()
			b.ResetTimer()

			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := next.Add(1) - 1
						if i >= int64(b.N) {
							return
						}
						if _, err := w.Write(ctx, pairs[i], "bench", DefaultProjectUUID); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
