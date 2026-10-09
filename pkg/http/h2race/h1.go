package h2race

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// LastByteSync is the HTTP/1.1 fallback for SinglePacket: it opens one
// connection per request, writes each request minus its final byte, waits
// opts.Settle, then writes every final byte in a tight loop and reads one
// response per connection.
//
// The returned slice is index-aligned with reqs. A failure to open or prime
// any connection is returned as the error (every connection is closed): a
// batch with a missing member is not a synchronised batch.
func LastByteSync(ctx context.Context, t Target, reqs []Request, opts Options) ([]Response, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	wires := make([][]byte, len(reqs))
	for i, r := range reqs {
		wires[i] = r.WireH1()
		if len(wires[i]) == 0 {
			return nil, ErrEmptyRequest
		}
	}

	conns := make([]net.Conn, len(reqs))
	errs := make([]error, len(reqs))
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], _, errs[i] = dial(ctx, t, opts, []string{"http/1.1"})
		}(i)
	}
	wg.Wait()
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	defer close(done)
	watchContext(ctx, done, conns...)

	deadline := time.Now().Add(opts.timeout())
	for i, c := range conns {
		_ = c.SetDeadline(deadline)
		if _, err := c.Write(wires[i][:len(wires[i])-1]); err != nil {
			return nil, err
		}
	}
	if opts.Settle > 0 {
		select {
		case <-time.After(opts.Settle):
		case <-ctx.Done():
		}
	}

	sentAt := make([]time.Time, len(conns))
	for i, c := range conns {
		sentAt[i] = time.Now()
		if _, err := c.Write(wires[i][len(wires[i])-1:]); err != nil {
			return nil, err
		}
	}

	out := make([]Response, len(reqs))
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = readH1(conns[i], reqs[i].Method, sentAt[i], opts.maxBody())
		}(i)
	}
	wg.Wait()
	return out, nil
}

// readH1 reads one HTTP/1.1 response off c.
func readH1(c net.Conn, method string, sentAt time.Time, maxBody int) Response {
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	r := Response{Proto: "HTTP/1.1", Elapsed: time.Since(sentAt)}
	if err != nil {
		r.Err = classifyReadErr(err)
		return r
	}
	defer func() { _ = resp.Body.Close() }()
	r.Status = resp.StatusCode
	r.Header = resp.Header
	body, truncated, err := drain(resp.Body, maxBody)
	r.Body, r.Truncated = body, truncated
	if err != nil {
		r.Err = classifyReadErr(err)
	}
	return r
}

func classifyReadErr(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.Join(ErrRefused, err)
	}
	return err
}

// drain reads up to limit bytes of r, reporting whether more remained.
func drain(r io.Reader, limit int) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(body) > limit {
		return body[:limit], true, err
	}
	return body, false, err
}
